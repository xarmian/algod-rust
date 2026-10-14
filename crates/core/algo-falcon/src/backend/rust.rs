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

//! The pure-Rust backend adapter over `crate::rs::det1024`.
//!
//! DIVERGENCE DIV-001: go-algorand calls the C library through cgo; algod-rust
//! implements deterministic Falcon-1024 in Rust (`crate::rs`, Phase 21, epic
//! #1926) and keeps the C library as a selectable backend. The functions
//! here mirror `backend::c` one for one, returning the same numeric codes
//! (`FALCON_ERR_*`) in the same `FalconError` variants, so the two backends
//! are observationally identical. See `docs/DIVERGENCES.md`.

use crate::rs::det1024;
use crate::rs::shake256::Shake256;
use crate::{
    FalconError, FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE,
    FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_SIG_CT_SIZE,
};

/// `falcon_det1024_verify_compressed`. Sizes are pre-validated by the caller.
pub(crate) fn verify(pubkey: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, FalconError> {
    debug_assert_eq!(pubkey.len(), FALCON_DET1024_PUBKEY_SIZE);
    debug_assert!(sig.len() >= 2 && sig.len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
    Ok(det1024::verify_compressed_det(sig, pubkey, data) == 0)
}

/// `shake256_init_prng_from_seed` + `falcon_det1024_keygen`.
pub(crate) fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    let mut rng = Shake256::prng_from_seed(seed);
    let mut pubkey = vec![0u8; FALCON_DET1024_PUBKEY_SIZE];
    let mut privkey = vec![0u8; FALCON_DET1024_PRIVKEY_SIZE];
    let rc = det1024::keygen(&mut rng, &mut privkey, &mut pubkey);
    if rc != 0 {
        return Err(FalconError::KeygenFailed(rc));
    }
    Ok((pubkey, privkey))
}

/// `falcon_det1024_sign_compressed`. The private key size is pre-validated.
pub(crate) fn sign(privkey: &[u8], data: &[u8]) -> Result<Vec<u8>, FalconError> {
    debug_assert_eq!(privkey.len(), FALCON_DET1024_PRIVKEY_SIZE);
    let mut sig = vec![0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
    let mut sig_len = FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;
    let rc = det1024::sign_compressed(&mut sig, &mut sig_len, privkey, data);
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
    let rc = det1024::convert_compressed_to_ct(&mut sig_ct, sig_compressed);
    if rc != 0 {
        return Err(FalconError::ConvertToCtFailed(rc));
    }
    Ok(sig_ct)
}

/// `falcon_det1024_get_salt_version` (the caller guarantees `sig.len() >= 2`).
pub(crate) fn salt_version(sig: &[u8]) -> Result<u8, FalconError> {
    debug_assert!(sig.len() >= 2);
    let rc = det1024::get_salt_version(sig);
    if rc < 0 {
        return Err(FalconError::SaltVersionFailed(rc));
    }
    Ok(rc as u8)
}
