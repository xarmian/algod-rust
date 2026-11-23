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

//! The signature-byte verifiers of the `SaltedKeySig` schemes, mirroring
//! go-algorand v5.1's `crypto/sig_scheme.go` and `crypto/falconWrapper.go`
//! (`VerifyFalcon1024`, `VerifyFalcon512`):
//!
//! - which schemes exist, when they are enabled, what they cost and how big
//!   their keys and signatures may be is decided by the registry in
//!   `algo-types` (`ConsensusParams::sig_scheme_enabled`, the `*_SIZE` bounds)
//!   and `algo-validate`; these functions only check bytes;
//! - every failure reads as go's does: `<scheme> invalid signature: <why>`
//!   (`ErrSigInvalid` wrapped with the scheme name).

use algo_falcon::{FalconError, FALCON_DET1024_PUBKEY_SIZE, FALCON_DET512_PUBKEY_SIZE};

/// go's `crypto.ErrSigInvalid`.
pub const ERR_SIG_INVALID: &str = "invalid signature";

/// Why a scheme's verifier refused a signature (Go: the `error` returned by
/// `SigSchemeVerifier.Verify`). Each `Display`s as go's text.
#[derive(Debug, Clone, PartialEq)]
pub enum SigVerifyError {
    /// The public key is not the scheme's size. go:
    /// `fmt.Errorf("falcon-1024 %w: public key size %d, want %d", ErrSigInvalid, ...)`.
    PublicKeySize {
        scheme: &'static str,
        got: usize,
        want: usize,
    },
    /// An empty signature. go's `cfalcon` `PublicKey.Verify`:
    /// `fmt.Errorf("empty signature: %w", ErrVerifyFail)`, wrapped.
    EmptySignature { scheme: &'static str },
    /// The verifier rejected the signature with this `FALCON_ERR_*` code.
    /// go's `cfalcon`: `fmt.Errorf("error code %d: %w", r, ErrVerifyFail)`.
    VerifyFailed { scheme: &'static str, code: i32 },
    /// Any other failure of the Falcon layer (not produced for inputs that
    /// passed the size checks).
    Backend {
        scheme: &'static str,
        message: String,
    },
}

impl std::fmt::Display for SigVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigVerifyError::PublicKeySize { scheme, got, want } => write!(
                f,
                "{scheme} {ERR_SIG_INVALID}: public key size {got}, want {want}"
            ),
            SigVerifyError::EmptySignature { scheme } => write!(
                f,
                "{scheme} {ERR_SIG_INVALID}: empty signature: falcon verify failed"
            ),
            SigVerifyError::VerifyFailed { scheme, code } => write!(
                f,
                "{scheme} {ERR_SIG_INVALID}: error code {code}: falcon verify failed"
            ),
            SigVerifyError::Backend { scheme, message } => {
                write!(f, "{scheme} {ERR_SIG_INVALID}: {message}")
            }
        }
    }
}

impl std::error::Error for SigVerifyError {}

fn falcon_error(scheme: &'static str, want: usize, e: FalconError) -> SigVerifyError {
    match e {
        FalconError::InvalidPubkeySize(got) => SigVerifyError::PublicKeySize { scheme, got, want },
        other => SigVerifyError::Backend {
            scheme,
            message: other.to_string(),
        },
    }
}

/// go's `crypto.VerifyFalcon1024` over raw to-be-signed `message` bytes: the
/// key size, then the verifier, which rejects an empty signature before any work.
pub fn verify_falcon1024(
    message: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), SigVerifyError> {
    const NAME: &str = "falcon-1024";
    if public_key.len() != FALCON_DET1024_PUBKEY_SIZE {
        return Err(SigVerifyError::PublicKeySize {
            scheme: NAME,
            got: public_key.len(),
            want: FALCON_DET1024_PUBKEY_SIZE,
        });
    }
    if signature.is_empty() {
        return Err(SigVerifyError::EmptySignature { scheme: NAME });
    }
    match algo_falcon::falcon_verify_code(public_key, signature, message)
        .map_err(|e| falcon_error(NAME, FALCON_DET1024_PUBKEY_SIZE, e))?
    {
        0 => Ok(()),
        code => Err(SigVerifyError::VerifyFailed { scheme: NAME, code }),
    }
}

/// go's `crypto.VerifyFalcon512` (falcon v0.2.0's `Det512`), as above.
pub fn verify_falcon512(
    message: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), SigVerifyError> {
    const NAME: &str = "falcon-512";
    if public_key.len() != FALCON_DET512_PUBKEY_SIZE {
        return Err(SigVerifyError::PublicKeySize {
            scheme: NAME,
            got: public_key.len(),
            want: FALCON_DET512_PUBKEY_SIZE,
        });
    }
    if signature.is_empty() {
        return Err(SigVerifyError::EmptySignature { scheme: NAME });
    }
    match algo_falcon::falcon512_verify_code(public_key, signature, message)
        .map_err(|e| falcon_error(NAME, FALCON_DET512_PUBKEY_SIZE, e))?
    {
        0 => Ok(()),
        code => Err(SigVerifyError::VerifyFailed { scheme: NAME, code }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_falcon::{FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET512_SIG_COMPRESSED_MAXSIZE};

    /// The wire bounds `algo-types` carries are the sizes the falcon crate
    /// produces.
    #[test]
    fn wire_bounds_match_the_falcon_crate() {
        use algo_types::go_msgp as r;
        assert_eq!(r::FALCON1024_PUBLIC_KEY_SIZE, FALCON_DET1024_PUBKEY_SIZE);
        assert_eq!(
            r::FALCON1024_MAX_SIGNATURE_SIZE,
            FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
        );
        assert_eq!(r::FALCON512_PUBLIC_KEY_SIZE, FALCON_DET512_PUBKEY_SIZE);
        assert_eq!(
            r::FALCON512_MAX_SIGNATURE_SIZE,
            FALCON_DET512_SIG_COMPRESSED_MAXSIZE
        );
    }

    #[test]
    fn falcon1024_round_trip_and_rejections() {
        let seed = [1u8; algo_falcon::FALCON_SEED_SIZE];
        let (pk, sk) = algo_falcon::falcon_keygen(&seed).unwrap();
        let sig = algo_falcon::falcon_sign(&sk, b"msg").unwrap();
        verify_falcon1024(b"msg", &pk, &sig).unwrap();
        let e = verify_falcon1024(b"other", &pk, &sig).unwrap_err();
        assert!(
            e.to_string()
                .starts_with("falcon-1024 invalid signature: error code -4"),
            "{e}"
        );
        assert_eq!(
            verify_falcon1024(b"msg", &pk[1..], &sig)
                .unwrap_err()
                .to_string(),
            "falcon-1024 invalid signature: public key size 1792, want 1793"
        );
        assert_eq!(
            verify_falcon1024(b"msg", &pk, &[]).unwrap_err().to_string(),
            "falcon-1024 invalid signature: empty signature: falcon verify failed"
        );
    }

    #[test]
    fn falcon512_round_trip_and_rejections() {
        let (pk, sk) = algo_falcon::falcon512_keygen(&[2u8; 32]).unwrap();
        let sig = algo_falcon::falcon512_sign(&sk, b"msg").unwrap();
        verify_falcon512(b"msg", &pk, &sig).unwrap();
        assert!(verify_falcon512(b"other", &pk, &sig).is_err());
        assert_eq!(
            verify_falcon512(b"msg", &pk[1..], &sig)
                .unwrap_err()
                .to_string(),
            "falcon-512 invalid signature: public key size 896, want 897"
        );
        // A 1024 key is not a 512 key.
        assert!(verify_falcon512(b"msg", &[0u8; 1793], &sig).is_err());
    }
}
