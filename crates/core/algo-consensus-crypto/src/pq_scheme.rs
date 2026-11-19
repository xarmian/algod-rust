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

//! Post-quantum (PQ) signature scheme dispatch, mirroring go-algorand's
//! `crypto/pq_scheme.go`:
//!
//! - [`lookup_pq_scheme`] is a scheme-tag → verifier dispatch table
//!   (`crypto.LookupPQScheme`) — the point is *bounding/validating an
//!   untrusted scheme tag* before any verification is attempted, not
//!   supporting multiple schemes today. Only Falcon-1024 (`"f1"`) is
//!   registered, matching upstream (the reserved `"f2"`/Falcon-512 tag is a
//!   known constant with no registered verifier, also matching upstream's
//!   commented-out case).
//! - [`MAX_PQ_PUBLIC_KEY_SIZE`]/[`MAX_PQ_SIGNATURE_SIZE`] are the wire/decode
//!   bounds across all registered schemes (`crypto.MaxPQPublicKeySize`/
//!   `MaxPQSignatureSize`), used to size decode buffers safely. Adding a
//!   scheme with a larger key or signature means growing these constants;
//!   `test_pq_bounds_cover_falcon1024` guards against undersizing the
//!   current schemes, mirroring upstream's `TestPQBoundsCoverFalcon1024`.

use algo_falcon::{FalconError, FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE};

/// The largest public-key size over all supported PQ schemes (Go:
/// `crypto.MaxPQPublicKeySize`).
pub const MAX_PQ_PUBLIC_KEY_SIZE: usize = FALCON_DET1024_PUBKEY_SIZE;

/// The largest signature size over all supported PQ schemes (Go:
/// `crypto.MaxPQSignatureSize`).
pub const MAX_PQ_SIGNATURE_SIZE: usize = FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;

/// Verifies a post-quantum signature for one scheme (Go: `crypto.PQVerifier`).
pub trait PQVerifier {
    /// Verify `signature` over raw to-be-signed `message` bytes under
    /// `public_key`. Returns `Ok(())` only if the signature is
    /// cryptographically valid; any other outcome (malformed input, bad
    /// signature) is an `Err`.
    fn verify(
        &self,
        message: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), PQVerifyError>;
}

/// go's `crypto.ErrPQFalcon1024SigInvalid` (`crypto/falconWrapper.go`), which
/// `VerifyFalcon1024` wraps for every failed Falcon-1024 verification.
pub const ERR_PQ_FALCON1024_SIG_INVALID: &str = "invalid falcon-1024 signature";

/// Errors from a [`PQVerifier`] (Go: the `error` returned by
/// `PQVerifier.Verify`). Each `Display`s as go's text.
#[derive(Debug, Clone, PartialEq)]
pub enum PQVerifyError {
    /// The public key is not a Falcon-1024 key's size. go:
    /// `fmt.Errorf("%w: public key size %d, want %d", ErrPQFalcon1024SigInvalid, ...)`.
    PublicKeySize(usize),
    /// An empty signature. go's `cfalcon` `PublicKey.Verify`:
    /// `fmt.Errorf("empty signature: %w", ErrVerifyFail)`, wrapped.
    EmptySignature,
    /// The verifier rejected the signature with this `FALCON_ERR_*` code.
    /// go's `cfalcon`: `fmt.Errorf("error code %d: %w", r, ErrVerifyFail)`,
    /// wrapped as `fmt.Errorf("%w: %w", ErrPQFalcon1024SigInvalid, err)`.
    VerifyFailed(i32),
    /// Any other failure of the Falcon layer (not produced for inputs that
    /// passed the size checks above).
    Backend(String),
}

impl std::fmt::Display for PQVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PQVerifyError::PublicKeySize(n) => write!(
                f,
                "{ERR_PQ_FALCON1024_SIG_INVALID}: public key size {n}, want {FALCON_DET1024_PUBKEY_SIZE}"
            ),
            PQVerifyError::EmptySignature => write!(
                f,
                "{ERR_PQ_FALCON1024_SIG_INVALID}: empty signature: falcon verify failed"
            ),
            PQVerifyError::VerifyFailed(rc) => write!(
                f,
                "{ERR_PQ_FALCON1024_SIG_INVALID}: error code {rc}: falcon verify failed"
            ),
            PQVerifyError::Backend(msg) => write!(f, "{ERR_PQ_FALCON1024_SIG_INVALID}: {msg}"),
        }
    }
}

impl std::error::Error for PQVerifyError {}

impl From<FalconError> for PQVerifyError {
    fn from(e: FalconError) -> Self {
        match e {
            FalconError::InvalidPubkeySize(n) => PQVerifyError::PublicKeySize(n),
            other => PQVerifyError::Backend(other.to_string()),
        }
    }
}

/// The Falcon-1024 (`"f1"`) scheme (Go: the unexported `falcon1024` type in
/// `crypto/pq_scheme.go`, which calls `crypto.VerifyFalcon1024`).
struct Falcon1024;

impl PQVerifier for Falcon1024 {
    fn verify(
        &self,
        message: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), PQVerifyError> {
        // go's `VerifyFalcon1024` order: the key size, then the C verifier,
        // which rejects an empty signature before any work.
        if public_key.len() != FALCON_DET1024_PUBKEY_SIZE {
            return Err(PQVerifyError::PublicKeySize(public_key.len()));
        }
        if signature.is_empty() {
            return Err(PQVerifyError::EmptySignature);
        }
        match algo_falcon::falcon_verify_code(public_key, signature, message)? {
            0 => Ok(()),
            rc => Err(PQVerifyError::VerifyFailed(rc)),
        }
    }
}

/// Returns the verifier for a PQ scheme tag, or `None` if the tag names no
/// registered scheme. Mirrors go's `crypto.LookupPQScheme(s protocol.PQScheme)
/// (PQVerifier, bool)`.
///
/// To add a scheme: add a case here returning its [`PQVerifier`], and grow
/// [`MAX_PQ_PUBLIC_KEY_SIZE`]/[`MAX_PQ_SIGNATURE_SIZE`] if its public key or
/// signature is larger (see `test_pq_bounds_cover_falcon1024`).
pub fn lookup_pq_scheme(scheme: [u8; 2]) -> Option<Box<dyn PQVerifier>> {
    match &scheme {
        b"f1" => Some(Box::new(Falcon1024)),
        // b"f2" => reserved for Falcon-512, not registered (matches upstream).
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors go's `TestLookupPQScheme`: the registered tag resolves to a
    /// verifier, and an unregistered/malformed tag resolves to nothing.
    #[test]
    fn test_lookup_pq_scheme() {
        assert!(lookup_pq_scheme(*b"f1").is_some());

        // "f2" (Falcon-512) is a known-but-unregistered upstream constant.
        assert!(lookup_pq_scheme(*b"f2").is_none());
        // Arbitrary malformed/unknown tags must also be rejected.
        assert!(lookup_pq_scheme(*b"x1").is_none());
        assert!(lookup_pq_scheme([0u8, 0u8]).is_none());
        assert!(lookup_pq_scheme([0xffu8, 0xffu8]).is_none());
    }

    /// Mirrors go's `TestPQBoundsCoverFalcon1024`: a real Falcon-1024 keypair
    /// and signature must fit within the advertised bounds.
    #[test]
    fn test_pq_bounds_cover_falcon1024() {
        let seed = [1u8; algo_falcon::FALCON_SEED_SIZE];
        let (pubkey, privkey) = algo_falcon::falcon_keygen(&seed).expect("keygen should succeed");
        assert!(pubkey.len() <= MAX_PQ_PUBLIC_KEY_SIZE);

        let sig = algo_falcon::falcon_sign(&privkey, b"pq bounds").expect("sign should succeed");
        assert!(sig.len() <= MAX_PQ_SIGNATURE_SIZE);
    }

    /// Mirrors go's `TestPQVerifierFalcon1024RoundTrip`: dispatching through
    /// `lookup_pq_scheme` produces a verifier that accepts a genuine
    /// signature and rejects a missing/invalid one.
    #[test]
    fn test_pq_verifier_falcon1024_round_trip() {
        let verifier = lookup_pq_scheme(*b"f1").expect("f1 must be registered");

        let seed = [1u8; algo_falcon::FALCON_SEED_SIZE];
        let (pubkey, privkey) = algo_falcon::falcon_keygen(&seed).expect("keygen should succeed");
        let msg = b"pq verifier round trip";
        let sig = algo_falcon::falcon_sign(&privkey, msg).expect("sign should succeed");

        assert!(verifier.verify(msg, &pubkey, &sig).is_ok());
        assert!(verifier.verify(msg, &pubkey, &[]).is_err());
    }

    /// go's `VerifyFalcon1024` texts (`crypto/falconWrapper.go`, v5.0.5):
    /// the key size first, then the wrapped `cfalcon` error (issue #2438).
    #[test]
    fn test_falcon1024_failure_texts_match_go() {
        let verifier = lookup_pq_scheme(*b"f1").expect("f1 must be registered");
        let seed = [3u8; algo_falcon::FALCON_SEED_SIZE];
        let (pubkey, privkey) = algo_falcon::falcon_keygen(&seed).expect("keygen should succeed");
        let sig = algo_falcon::falcon_sign(&privkey, b"m").expect("sign should succeed");
        let text = |pk: &[u8], s: &[u8]| verifier.verify(b"m", pk, s).unwrap_err().to_string();

        assert_eq!(
            text(&pubkey[1..], &[]),
            "invalid falcon-1024 signature: public key size 1792, want 1793"
        );
        assert_eq!(
            text(&pubkey, &[]),
            "invalid falcon-1024 signature: empty signature: falcon verify failed"
        );
        assert_eq!(
            text(&pubkey, &sig[..1]),
            "invalid falcon-1024 signature: error code -4: falcon verify failed"
        );
        let mut tampered = sig.clone();
        tampered[0] ^= 1;
        assert_eq!(
            text(&pubkey, &tampered),
            "invalid falcon-1024 signature: error code -4: falcon verify failed"
        );
    }
}
