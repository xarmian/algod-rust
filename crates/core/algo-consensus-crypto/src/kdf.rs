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

//! Key-derivation function wrappers.
//!
//! Currently a thin shim over the [`scrypt`] crate for the parameters
//! used by Algorand's KMD wallet driver. Exposed here so the
//! consensus-crypto crate owns "the workspace's scrypt entry point" and
//! downstream consumers (e.g. `algo-kmd`) don't each pull `scrypt`
//! directly. Go reference: `daemon/kmd/wallet/driver/sqlite_crypto.go:79`
//! (`scrypt.Key(password, salt, N, r, p, keyLen)`).

use scrypt::scrypt;

/// Error returned by [`scrypt_key`] when the supplied parameters are
/// rejected by the underlying scrypt implementation (e.g. invalid `N`,
/// `r`, or `p`).
#[derive(Debug, thiserror::Error)]
#[error("scrypt key derivation failed: {0}")]
pub struct ScryptError(String);

/// Derive a `key_len`-byte key from `password` and `salt` using scrypt
/// with the given cost parameters. Mirrors Go's
/// `scrypt.Key(password, salt, N, r, p, keyLen)` byte-for-byte —
/// caller is responsible for supplying parameters that match the wallet
/// (the kmd driver uses `(N, r, p) = (65536, 1, 32)` by default, see
/// [`algo_kmd::DEFAULT_SCRYPT_N`] et al).
///
/// `n` is the scrypt CPU/memory cost; `r` is the block size; `p` is the
/// parallelization parameter. The `scrypt` crate expects `n` as `log2(N)`,
/// so this wrapper takes the raw `N` value and converts internally to
/// keep the call site identical to Go.
pub fn scrypt_key(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    key_len: usize,
) -> Result<Vec<u8>, ScryptError> {
    let log_n =
        log2_exact(n).ok_or_else(|| ScryptError(format!("N must be a power of 2, got {n}")))?;
    let params = scrypt::Params::new(log_n, r, p, key_len)
        .map_err(|e| ScryptError(format!("invalid scrypt params: {e}")))?;
    let mut out = vec![0u8; key_len];
    scrypt(password, salt, &params, &mut out).map_err(|e| ScryptError(format!("scrypt: {e}")))?;
    Ok(out)
}

fn log2_exact(n: u32) -> Option<u8> {
    if n == 0 || !n.is_power_of_two() {
        return None;
    }
    Some(n.trailing_zeros() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_exact_rejects_non_power_of_two() {
        assert_eq!(log2_exact(1), Some(0));
        assert_eq!(log2_exact(2), Some(1));
        assert_eq!(log2_exact(1024), Some(10));
        assert_eq!(log2_exact(65536), Some(16));
        assert_eq!(log2_exact(0), None);
        assert_eq!(log2_exact(3), None);
        assert_eq!(log2_exact(65535), None);
    }

    #[test]
    fn rfc7914_test_vector() {
        // RFC 7914 §12: scrypt(P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64)
        let expected = hex::decode(
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        )
        .unwrap();
        let got = scrypt_key(b"password", b"NaCl", 1024, 8, 16, 64).unwrap();
        assert_eq!(got, expected);
    }
}
