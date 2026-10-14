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

//! The public Falcon API layer (`falcon.c`): key encoding, the
//! compressed-signature signing and verification entry points, with the
//! C's error codes.
//!
//! Ported from the Falcon reference implementation, `falcon-c/falcon.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! Only what `det1024` reaches is ported: `falcon_get_logn`,
//! `falcon_keygen_make`, `falcon_sign_dyn_finish` for
//! `FALCON_SIG_COMPRESSED`, and `falcon_verify` for compressed signatures.
//! Note that in compressed mode both signing and verification hash the
//! message with `hash_to_point_vartime` (the constant-time variant is used
//! only for CT-format signatures).

use super::codec::{
    comp_decode, comp_encode, modq_decode, modq_encode, trim_i8_decode, trim_i8_encode,
    MAX_FG_BITS, MAX_FG_BITS_BIG,
};
use super::common::hash_to_point_vartime;
use super::keygen::keygen;
use super::shake256::Shake256;
use super::sign::sign_dyn;
use super::vrfy::{complete_private, compute_public, to_ntt_monty, verify_raw};

/// `FALCON_ERR_*` codes (`falcon.h`).
pub(crate) const FALCON_ERR_RANDOM: i32 = -1;
pub(crate) const FALCON_ERR_SIZE: i32 = -2;
pub(crate) const FALCON_ERR_FORMAT: i32 = -3;
pub(crate) const FALCON_ERR_BADSIG: i32 = -4;
pub(crate) const FALCON_ERR_BADARG: i32 = -5;
pub(crate) const FALCON_ERR_INTERNAL: i32 = -6;

/// `FALCON_PRIVKEY_SIZE(logn)`.
pub(crate) const fn privkey_size(logn: u32) -> usize {
    let n = 1usize << logn;
    let fg_bits = if logn <= 1 {
        8
    } else {
        MAX_FG_BITS[logn as usize] as usize
    };
    1 + ((n * fg_bits + 7) >> 3) * 2 + ((n * MAX_FG_BITS_BIG[logn as usize] as usize + 7) >> 3)
}

/// `FALCON_PUBKEY_SIZE(logn)`.
pub(crate) const fn pubkey_size(logn: u32) -> usize {
    let n = 1usize << logn;
    1 + ((n * 14 + 7) >> 3)
}

/// `FALCON_SIG_COMPRESSED_MAXSIZE(logn)` (salted format, 40-byte nonce).
pub(crate) const fn sig_compressed_maxsize(logn: u32) -> usize {
    ((((11usize << logn) + (101usize >> (10 - logn))) + 6) >> 3) + 41
}

/// `falcon_get_logn`.
pub(crate) fn get_logn(obj: &[u8]) -> i32 {
    if obj.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    let logn = i32::from(obj[0] & 0x0F);
    if !(1..=10).contains(&logn) {
        return FALCON_ERR_FORMAT;
    }
    logn
}

/// `falcon_keygen_make`: generate and encode a key pair.
pub(crate) fn keygen_make(
    rng: &mut Shake256,
    logn: u32,
    privkey: &mut [u8],
    pubkey: Option<&mut [u8]>,
) -> i32 {
    if !(1..=10).contains(&logn) {
        return FALCON_ERR_BADARG;
    }
    let sk_len = privkey_size(logn);
    let pk_len = pubkey_size(logn);
    if privkey.len() < sk_len {
        return FALCON_ERR_SIZE;
    }
    if let Some(pk) = &pubkey {
        if pk.len() < pk_len {
            return FALCON_ERR_SIZE;
        }
    }
    let n = 1usize << logn;
    let mut f = vec![0i8; n];
    let mut g = vec![0i8; n];
    let mut big_f = vec![0i8; n];
    keygen(rng, &mut f, &mut g, &mut big_f, None, None, logn);

    let sk = &mut privkey[..sk_len];
    sk[0] = 0x50 + logn as u8;
    let mut u = 1usize;
    let v = trim_i8_encode(
        Some(&mut sk[u..]),
        &f,
        logn,
        u32::from(MAX_FG_BITS[logn as usize]),
    );
    if v == 0 {
        return FALCON_ERR_INTERNAL;
    }
    u += v;
    let v = trim_i8_encode(
        Some(&mut sk[u..]),
        &g,
        logn,
        u32::from(MAX_FG_BITS[logn as usize]),
    );
    if v == 0 {
        return FALCON_ERR_INTERNAL;
    }
    u += v;
    let v = trim_i8_encode(
        Some(&mut sk[u..]),
        &big_f,
        logn,
        u32::from(MAX_FG_BITS_BIG[logn as usize]),
    );
    if v == 0 {
        return FALCON_ERR_INTERNAL;
    }
    u += v;
    if u != sk_len {
        return FALCON_ERR_INTERNAL;
    }

    if let Some(pubkey) = pubkey {
        let mut h = vec![0u16; n];
        if !compute_public(&mut h, &f, &g, logn) {
            return FALCON_ERR_INTERNAL;
        }
        let pk = &mut pubkey[..pk_len];
        pk[0] = logn as u8;
        let v = modq_encode(Some(&mut pk[1..]), &h, logn);
        if v != pk_len - 1 {
            return FALCON_ERR_INTERNAL;
        }
    }
    0
}

/// `falcon_sign_dyn_finish` for `FALCON_SIG_COMPRESSED`: `hash_data` has
/// had the nonce and the message injected (not yet flipped); `nonce` is
/// the 40-byte salt copied into the signature. On success `sig[..len]`
/// holds the salted compressed signature and `len` is returned in
/// `sig_len`.
pub(crate) fn sign_dyn_finish_compressed(
    rng: &mut Shake256,
    sig: &mut [u8],
    sig_len: &mut usize,
    privkey: &[u8],
    hash_data: &mut Shake256,
    nonce: &[u8; 40],
) -> i32 {
    if privkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if (privkey[0] & 0xF0) != 0x50 {
        return FALCON_ERR_FORMAT;
    }
    let logn = u32::from(privkey[0] & 0x0F);
    if !(1..=10).contains(&logn) {
        return FALCON_ERR_FORMAT;
    }
    if privkey.len() != privkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    let es_len = *sig_len;
    if es_len < 41 {
        return FALCON_ERR_SIZE;
    }
    let n = 1usize << logn;
    let mut f = vec![0i8; n];
    let mut g = vec![0i8; n];
    let mut big_f = vec![0i8; n];
    let mut big_g = vec![0i8; n];
    let mut u = 1usize;
    let v = trim_i8_decode(
        &mut f,
        logn,
        u32::from(MAX_FG_BITS[logn as usize]),
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = trim_i8_decode(
        &mut g,
        logn,
        u32::from(MAX_FG_BITS[logn as usize]),
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = trim_i8_decode(
        &mut big_f,
        logn,
        u32::from(MAX_FG_BITS_BIG[logn as usize]),
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    if u != privkey.len() {
        return FALCON_ERR_FORMAT;
    }
    if !complete_private(&mut big_g, &f, &g, &big_f, logn) {
        return FALCON_ERR_FORMAT;
    }

    // The C loops here only for FALCON_SIG_PADDED (retrying until the
    // encoding fits); for the compressed format one pass always returns.
    hash_data.flip();
    let mut hm = vec![0u16; n];
    let mut sv = vec![0i16; n];
    hash_to_point_vartime(hash_data, &mut hm, logn);
    sign_dyn(&mut sv, rng, &f, &g, &big_f, &big_g, &hm, logn);
    let es = &mut sig[..es_len];
    es[1..41].copy_from_slice(nonce);
    let u = 41usize;
    es[0] = 0x30 + logn as u8;
    let v = comp_encode(Some(&mut es[u..]), &sv, logn);
    if v == 0 {
        return FALCON_ERR_SIZE;
    }
    *sig_len = u + v;
    0
}

/// `falcon_verify` for a compressed-format (salted) signature.
pub(crate) fn verify_compressed(sig: &[u8], pubkey: &[u8], data: &[u8]) -> i32 {
    // falcon_verify_start
    if sig.len() < 41 {
        return FALCON_ERR_FORMAT;
    }
    let mut hd = Shake256::new();
    hd.inject(&sig[1..41]);
    hd.inject(data);
    // falcon_verify_finish(sig_type = FALCON_SIG_COMPRESSED)
    if pubkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if (pubkey[0] & 0xF0) != 0x00 {
        return FALCON_ERR_FORMAT;
    }
    let logn = u32::from(pubkey[0] & 0x0F);
    if !(1..=10).contains(&logn) {
        return FALCON_ERR_FORMAT;
    }
    if u32::from(sig[0] & 0x0F) != logn {
        return FALCON_ERR_BADSIG;
    }
    if (sig[0] & 0xF0) != 0x30 {
        return FALCON_ERR_FORMAT;
    }
    if pubkey.len() != pubkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    let n = 1usize << logn;
    let mut h = vec![0u16; n];
    let mut hm = vec![0u16; n];
    let mut sv = vec![0i16; n];
    if modq_decode(&mut h, logn, &pubkey[1..]) != pubkey.len() - 1 {
        return FALCON_ERR_FORMAT;
    }
    let u = 41usize;
    let v = comp_decode(&mut sv, logn, &sig[u..]);
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    if u + v != sig.len() {
        return FALCON_ERR_FORMAT;
    }
    hd.flip();
    hash_to_point_vartime(&mut hd, &mut hm, logn);
    to_ntt_monty(&mut h, logn);
    if !verify_raw(&hm, &sv, &h, logn) {
        return FALCON_ERR_BADSIG;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_the_c_macros_for_logn_10() {
        assert_eq!(privkey_size(10), 2305);
        assert_eq!(pubkey_size(10), 1793);
        assert_eq!(sig_compressed_maxsize(10), 1462);
        assert_eq!(privkey_size(9), 1281);
        assert_eq!(pubkey_size(9), 897);
    }

    #[test]
    fn get_logn_parses_headers() {
        assert_eq!(get_logn(&[0x5a]), 10);
        assert_eq!(get_logn(&[0x0a]), 10);
        assert_eq!(get_logn(&[0x50]), FALCON_ERR_FORMAT);
        assert_eq!(get_logn(&[0x5b]), FALCON_ERR_FORMAT);
        assert_eq!(get_logn(&[]), FALCON_ERR_FORMAT);
    }
}
