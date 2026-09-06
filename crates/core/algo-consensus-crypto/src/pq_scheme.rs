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

/// Errors from a [`PQVerifier`] (Go: the `error` returned by
/// `PQVerifier.Verify`).
#[derive(Debug, Clone, PartialEq)]
pub enum PQVerifyError {
    /// The signature did not verify against the given message/public key.
    InvalidSignature,
    /// The underlying scheme implementation rejected malformed input
    /// (wrong-sized key/signature) before it could even attempt
    /// verification.
    MalformedInput(String),
}

impl std::fmt::Display for PQVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PQVerifyError::InvalidSignature => write!(f, "pq signature verification failed"),
            PQVerifyError::MalformedInput(msg) => write!(f, "malformed pq input: {msg}"),
        }
    }
}

impl std::error::Error for PQVerifyError {}

impl From<FalconError> for PQVerifyError {
    fn from(e: FalconError) -> Self {
        PQVerifyError::MalformedInput(e.to_string())
    }
}

/// The Falcon-1024 (`"f1"`) scheme (Go: the unexported `falcon1024` type in
/// `crypto/pq_scheme.go`).
struct Falcon1024;

impl PQVerifier for Falcon1024 {
    fn verify(
        &self,
        message: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), PQVerifyError> {
        if algo_falcon::falcon_verify(public_key, signature, message)? {
            Ok(())
        } else {
            Err(PQVerifyError::InvalidSignature)
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
}
