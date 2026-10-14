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

//! Algorand's deterministic Falcon-1024 (`det1024`), with two interchangeable
//! backends behind one API.
//!
//! **Important**: This is Algorand's custom *deterministic* Falcon-1024, NOT the
//! standard NIST Falcon submission. Key differences from standard Falcon:
//!
//! - Signing is fully deterministic (no random salt/nonce).
//! - Wire format replaces the 40-byte salt with a 1-byte salt version
//!   (currently version 0), reducing signature overhead.
//! - Custom header byte `0xBA` (compressed format: `0x3A | 0x80`) instead of
//!   the standard Falcon compressed header, signalling deterministic mode.
//! - The C library uses emulated floating-point (`FALCON_FPEMU=1`) to
//!   guarantee cross-platform determinism.
//!
//! Wire format sizes:
//! - Public key: 1793 bytes
//! - Max compressed signature: 1423 bytes (variable-length; actual sigs are shorter)
//! - Private key: 2305 bytes (not used on-chain, only for signing)
//!
//! Only the compressed-format deterministic variant is used on-chain.
//!
//! # Backends
//!
//! DIVERGENCE DIV-001: go-algorand links the C library
//! (`github.com/algorand/falcon` v0.1.0) through cgo; algod-rust implements the
//! same algorithm in pure Rust and keeps the vendored C as a runtime-selectable
//! backend ([`FalconBackend`], `config.json` `FalconBackend`). Both must be
//! byte-identical — see `docs/DIVERGENCES.md` and
//! `tests/fixtures/falcon/vectors.jsonl`.
//!
//! - [`FalconBackend::C`] (cargo feature `c-backend`, on by default): the
//!   vendored C sources in `falcon-c/`, compiled by `build.rs`.
//! - [`FalconBackend::Rust`] (the default): the pure-Rust port
//!   (`backend::rust` over `rs::det1024`, Phase 21, epic #1926).
//!
//! The process-wide backend is chosen once with [`set_falcon_backend`]
//! (the node does this from `config.json` at startup) and read with
//! [`falcon_backend`]; the plain `falcon_*` functions use it, the `*_with`
//! variants take an explicit backend (benchmarks, tests, generators).

use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

mod backend;
#[cfg(all(test, feature = "c-backend"))]
mod c_internals;
mod rs;

// ---------------------------------------------------------------------------
// Constants (computed from the C macros with logn=10)
// ---------------------------------------------------------------------------

/// Size of a Falcon-1024 public key in bytes.
pub const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;

/// Size of a Falcon-1024 private key in bytes.
pub const FALCON_DET1024_PRIVKEY_SIZE: usize = 2305;

/// Maximum size of a deterministic compressed-format signature.
/// Actual signatures are variable-length and usually shorter.
pub const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: usize = 1423;

/// Size of a deterministic CT-format (constant-time) signature.
pub const FALCON_DET1024_SIG_CT_SIZE: usize = 1538;

/// Seed size used for deterministic key generation: 32 bytes (256-bit
/// entropy), matching go-algorand's `crypto.FalconSeedSize`
/// (`crypto/falconWrapper.go`) as of commit `569ae3d4b` ("txn: native PQ
/// accounts (#6639)", first released in `v5.0.0-beta`). The previous value
/// of 48 was inherited from falcon.c's SHAKE256 explicit-seed API and did
/// not reflect a deliberate entropy choice.
pub const FALCON_SEED_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

/// Which implementation of `det1024` the `falcon_*` functions run.
///
/// DIVERGENCE DIV-001: this selector has no go-algorand counterpart.
///
/// The default is [`FalconBackend::Rust`] (since Phase 21 stage 11, #1937);
/// without the `c-backend` feature it is the only variant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FalconBackend {
    /// The pure-Rust implementation (`src/rs/`).
    #[default]
    Rust,
    /// The vendored C library (`falcon-c/`, github.com/algorand/falcon v0.1.0).
    #[cfg(feature = "c-backend")]
    C,
}

impl FalconBackend {
    /// The config-file / CLI spelling of this backend (`"rust"` / `"c"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            FalconBackend::Rust => "rust",
            #[cfg(feature = "c-backend")]
            FalconBackend::C => "c",
        }
    }

    /// Every backend compiled into this build.
    pub const fn all() -> &'static [FalconBackend] {
        #[cfg(feature = "c-backend")]
        {
            &[FalconBackend::C, FalconBackend::Rust]
        }
        #[cfg(not(feature = "c-backend"))]
        {
            &[FalconBackend::Rust]
        }
    }
}

impl fmt::Display for FalconBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error from parsing a [`FalconBackend`] name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownFalconBackend(pub String);

impl fmt::Display for UnknownFalconBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known: Vec<&str> = FalconBackend::all().iter().map(|b| b.as_str()).collect();
        write!(
            f,
            "unknown falcon backend {:?} (this build supports: {})",
            self.0,
            known.join(", ")
        )
    }
}

impl std::error::Error for UnknownFalconBackend {}

impl FromStr for FalconBackend {
    type Err = UnknownFalconBackend;

    /// Case-insensitive: `"rust"` or `"c"`. A name that is a real backend but
    /// not compiled into this build (`"c"` without the `c-backend` feature)
    /// is an error too, so a node never silently runs a different backend
    /// than its `config.json` asks for.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        FalconBackend::all()
            .iter()
            .copied()
            .find(|b| b.as_str() == lower)
            .ok_or_else(|| UnknownFalconBackend(s.to_string()))
    }
}

static BACKEND: OnceLock<FalconBackend> = OnceLock::new();

/// The process-wide backend used by the plain `falcon_*` functions.
/// Initialises to [`FalconBackend::default`] on first use.
pub fn falcon_backend() -> FalconBackend {
    *BACKEND.get_or_init(FalconBackend::default)
}

/// Choose the process-wide backend. Write-once: call it at startup, before
/// any `falcon_*` function runs (a `falcon_*` call pins the default). Setting
/// the backend that is already in effect is a no-op `Ok`; asking for a
/// different one returns `Err(current)` so the caller can fail loudly rather
/// than run with a backend other than the one it asked for.
pub fn set_falcon_backend(backend: FalconBackend) -> Result<(), FalconBackend> {
    let current = *BACKEND.get_or_init(|| backend);
    if current == backend {
        Ok(())
    } else {
        Err(current)
    }
}

// ---------------------------------------------------------------------------
// Public API: validate once, dispatch to the selected backend
// ---------------------------------------------------------------------------

fn check_pubkey(pubkey: &[u8]) -> Result<(), FalconError> {
    if pubkey.len() != FALCON_DET1024_PUBKEY_SIZE {
        return Err(FalconError::InvalidPubkeySize(pubkey.len()));
    }
    Ok(())
}

fn check_privkey(privkey: &[u8]) -> Result<(), FalconError> {
    if privkey.len() != FALCON_DET1024_PRIVKEY_SIZE {
        return Err(FalconError::InvalidPrivkeySize(privkey.len()));
    }
    Ok(())
}

/// Signatures must be 2..=1423 bytes: at least header + salt version, at
/// most the compressed maximum. `falcon_salt_version` relies on this bound
/// too — the C implementation reads `sig[1]` without a length check of its
/// own, and `sig` is attacker-controlled (decoded straight off an untrusted
/// block's wire bytes).
fn check_sig(sig: &[u8]) -> Result<(), FalconError> {
    if sig.len() < 2 || sig.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
        return Err(FalconError::InvalidSignatureSize(sig.len()));
    }
    Ok(())
}

/// Verify a deterministic Falcon-1024 compressed-format signature with the
/// process-wide backend.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if verification
/// fails (bad signature), or `Err` if the inputs are malformed (wrong sizes).
pub fn falcon_verify(pubkey: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, FalconError> {
    falcon_verify_with(falcon_backend(), pubkey, sig, data)
}

/// [`falcon_verify`] with an explicit backend.
pub fn falcon_verify_with(
    backend: FalconBackend,
    pubkey: &[u8],
    sig: &[u8],
    data: &[u8],
) -> Result<bool, FalconError> {
    check_pubkey(pubkey)?;
    check_sig(sig)?;
    match backend {
        FalconBackend::Rust => backend::rust::verify(pubkey, sig, data),
        #[cfg(feature = "c-backend")]
        FalconBackend::C => backend::c::verify(pubkey, sig, data),
    }
}

/// Generate a Falcon-1024 keypair `(pubkey, privkey)` from the given seed
/// with the process-wide backend.
///
/// The seed is used to initialize a SHAKE256 PRNG, producing deterministic keys
/// for a given seed value. Use a cryptographically random seed in production.
pub fn falcon_keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    falcon_keygen_with(falcon_backend(), seed)
}

/// [`falcon_keygen`] with an explicit backend.
pub fn falcon_keygen_with(
    backend: FalconBackend,
    seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    match backend {
        FalconBackend::Rust => backend::rust::keygen(seed),
        #[cfg(feature = "c-backend")]
        FalconBackend::C => backend::c::keygen(seed),
    }
}

/// Sign data with a Falcon-1024 private key, producing a compressed-format
/// deterministic signature, with the process-wide backend.
pub fn falcon_sign(privkey: &[u8], data: &[u8]) -> Result<Vec<u8>, FalconError> {
    falcon_sign_with(falcon_backend(), privkey, data)
}

/// [`falcon_sign`] with an explicit backend.
pub fn falcon_sign_with(
    backend: FalconBackend,
    privkey: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, FalconError> {
    check_privkey(privkey)?;
    match backend {
        FalconBackend::Rust => backend::rust::sign(privkey, data),
        #[cfg(feature = "c-backend")]
        FalconBackend::C => backend::c::sign(privkey, data),
    }
}

/// Convert a compressed-format deterministic Falcon-1024 signature to the
/// fixed-width "CT" (constant-time-decodable) representation, with the
/// process-wide backend.
///
/// This is the byte sequence go-algorand's `crypto.FalconSignature.
/// GetFixedLengthHashableRepresentation` (`crypto/falconWrapper.go:117`) feeds
/// into `merklesig::Signature`'s hashable representation for state-proof
/// commitments — the compressed wire encoding is variable-length, which is
/// unsuitable for a fixed-length hash-tree leaf, so it is expanded to a
/// canonical fixed-size form first (`falcon_det1024_convert_compressed_to_ct`,
/// `falcon-c/deterministic.h:105-114`).
pub fn falcon_convert_compressed_to_ct(
    sig_compressed: &[u8],
) -> Result<[u8; FALCON_DET1024_SIG_CT_SIZE], FalconError> {
    falcon_convert_compressed_to_ct_with(falcon_backend(), sig_compressed)
}

/// [`falcon_convert_compressed_to_ct`] with an explicit backend.
pub fn falcon_convert_compressed_to_ct_with(
    backend: FalconBackend,
    sig_compressed: &[u8],
) -> Result<[u8; FALCON_DET1024_SIG_CT_SIZE], FalconError> {
    check_sig(sig_compressed)?;
    match backend {
        FalconBackend::Rust => backend::rust::convert_compressed_to_ct(sig_compressed),
        #[cfg(feature = "c-backend")]
        FalconBackend::C => backend::c::convert_compressed_to_ct(sig_compressed),
    }
}

/// Return the salt version embedded in a Falcon signature (compressed or CT
/// form), matching go-algorand's `crypto.FalconSignature.IsSaltVersionEqual`
/// (`crypto/falconWrapper.go:127`), which compares this value against an
/// expected version. Uses the process-wide backend.
pub fn falcon_salt_version(sig: &[u8]) -> Result<u8, FalconError> {
    falcon_salt_version_with(falcon_backend(), sig)
}

/// [`falcon_salt_version`] with an explicit backend.
pub fn falcon_salt_version_with(backend: FalconBackend, sig: &[u8]) -> Result<u8, FalconError> {
    check_sig(sig)?;
    match backend {
        FalconBackend::Rust => backend::rust::salt_version(sig),
        #[cfg(feature = "c-backend")]
        FalconBackend::C => backend::c::salt_version(sig),
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the Falcon layer. The numeric codes are the C library's
/// (`FALCON_ERR_*`, `falcon-c/falcon.h`): `-1` size, `-2` format, `-3`
/// bad signature, `-4` bad argument, `-5` internal; the Rust backend reports
/// the same codes for the same conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FalconError {
    /// Public key has wrong length (expected 1793 bytes).
    InvalidPubkeySize(usize),
    /// Private key has wrong length (expected 2305 bytes).
    InvalidPrivkeySize(usize),
    /// Signature has invalid length (must be 2..=1423 bytes).
    InvalidSignatureSize(usize),
    /// Key generation returned a non-zero error code.
    KeygenFailed(i32),
    /// Signing returned a non-zero error code.
    SignFailed(i32),
    /// Compressed-to-CT conversion returned a non-zero error code.
    ConvertToCtFailed(i32),
    /// Salt-version extraction returned a negative error code.
    SaltVersionFailed(i32),
    /// The selected backend has no implementation of this operation in this
    /// build. Not produced by any current backend; kept for forward
    /// compatibility of the `#[non_exhaustive]` enum.
    BackendUnavailable(FalconBackend),
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalconError::InvalidPubkeySize(n) => {
                write!(
                    f,
                    "invalid falcon pubkey size {} (expected {})",
                    n, FALCON_DET1024_PUBKEY_SIZE
                )
            }
            FalconError::InvalidPrivkeySize(n) => {
                write!(
                    f,
                    "invalid falcon privkey size {} (expected {})",
                    n, FALCON_DET1024_PRIVKEY_SIZE
                )
            }
            FalconError::InvalidSignatureSize(n) => {
                write!(
                    f,
                    "invalid falcon signature size {} (max {})",
                    n, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
                )
            }
            FalconError::KeygenFailed(rc) => {
                write!(f, "falcon keygen failed with error code {}", rc)
            }
            FalconError::SignFailed(rc) => {
                write!(f, "falcon sign failed with error code {}", rc)
            }
            FalconError::ConvertToCtFailed(rc) => {
                write!(
                    f,
                    "falcon compressed-to-CT conversion failed with error code {}",
                    rc
                )
            }
            FalconError::SaltVersionFailed(rc) => {
                write!(f, "falcon salt version extraction failed with code {}", rc)
            }
            FalconError::BackendUnavailable(b) => {
                write!(f, "falcon backend {b} is not available in this build")
            }
        }
    }
}

impl std::error::Error for FalconError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod backend_tests {
    use super::*;

    #[test]
    fn backend_names_round_trip_and_unknown_is_rejected() {
        for b in FalconBackend::all() {
            assert_eq!(b.as_str().parse::<FalconBackend>(), Ok(*b));
            assert_eq!(
                b.to_string().to_uppercase().parse::<FalconBackend>(),
                Ok(*b)
            );
        }
        let err = "emulated".parse::<FalconBackend>().unwrap_err();
        assert_eq!(err, UnknownFalconBackend("emulated".to_string()));
        assert!(err.to_string().contains("rust"));
        #[cfg(not(feature = "c-backend"))]
        assert!("c".parse::<FalconBackend>().is_err());
    }

    #[test]
    fn set_falcon_backend_is_write_once_and_idempotent() {
        // Other tests in this binary may already have pinned the default by
        // calling a `falcon_*` function; the contract is the same either way.
        let d = falcon_backend();
        assert_eq!(set_falcon_backend(d), Ok(()));
        assert_eq!(set_falcon_backend(d), Ok(()));
        for other in FalconBackend::all().iter().copied().filter(|b| *b != d) {
            assert_eq!(set_falcon_backend(other), Err(d));
        }
        assert_eq!(falcon_backend(), d);
    }

    /// Every compiled backend produces identical keys, signatures, CT forms
    /// and verify decisions from the same inputs (the corpus test in
    /// `tests/falcon_vectors.rs` is the full-scale version of this).
    #[test]
    fn all_backends_agree_on_keygen_sign_verify() {
        let seed = [0x42u8; FALCON_SEED_SIZE];
        let msg = b"all backends agree";
        let results: Vec<_> = FalconBackend::all()
            .iter()
            .map(|&b| {
                let (pk, sk) = falcon_keygen_with(b, &seed).unwrap();
                let sig = falcon_sign_with(b, &sk, msg).unwrap();
                let ok = falcon_verify_with(b, &pk, &sig, msg).unwrap();
                let bad = falcon_verify_with(b, &pk, &sig, b"tampered").unwrap();
                let ct = falcon_convert_compressed_to_ct_with(b, &sig).unwrap();
                let salt = falcon_salt_version_with(b, &sig).unwrap();
                (pk, sk, sig, ok, bad, ct.to_vec(), salt)
            })
            .collect();
        for (b, r) in FalconBackend::all().iter().zip(&results) {
            assert!(r.3 && !r.4, "{b}: verify decisions");
            assert_eq!(
                r,
                &results[0],
                "{b} differs from {}",
                FalconBackend::all()[0]
            );
        }
        // Size validation happens before dispatch, identically for every backend.
        let pk = vec![0u8; FALCON_DET1024_PUBKEY_SIZE];
        let sig = vec![0xba, 0x00, 0x00];
        for &b in FalconBackend::all() {
            assert_eq!(
                falcon_verify_with(b, &pk[1..], &sig, b"x"),
                Err(FalconError::InvalidPubkeySize(
                    FALCON_DET1024_PUBKEY_SIZE - 1
                ))
            );
        }
    }

    #[test]
    fn explicit_c_backend_matches_default_dispatch() {
        #[cfg(feature = "c-backend")]
        {
            let seed = [7u8; FALCON_SEED_SIZE];
            let (pk, sk) = falcon_keygen_with(FalconBackend::C, &seed).unwrap();
            assert_eq!(falcon_keygen(&seed).unwrap(), (pk.clone(), sk.clone()));
            let sig = falcon_sign_with(FalconBackend::C, &sk, b"msg").unwrap();
            assert_eq!(falcon_sign(&sk, b"msg").unwrap(), sig);
            assert_eq!(
                falcon_verify_with(FalconBackend::C, &pk, &sig, b"msg"),
                Ok(true)
            );
            assert_eq!(falcon_salt_version_with(FalconBackend::C, &sig), Ok(0));
            assert_eq!(
                falcon_convert_compressed_to_ct_with(FalconBackend::C, &sig).unwrap(),
                falcon_convert_compressed_to_ct(&sig).unwrap()
            );
        }
    }
}

// These exercise the default (Rust) backend end to end; the C backend is
// covered by `all_backends_agree_on_keygen_sign_verify` and the corpus test.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify_roundtrip() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        assert_eq!(pubkey.len(), FALCON_DET1024_PUBKEY_SIZE);
        assert_eq!(privkey.len(), FALCON_DET1024_PRIVKEY_SIZE);

        let msg = b"hello falcon";
        let sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        assert!(!sig.is_empty());
        assert!(sig.len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);

        let result = falcon_verify(&pubkey, &sig, msg).expect("verify should not error");
        assert!(result, "signature should verify");
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let msg = b"correct message";
        let sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        let wrong_msg = b"wrong message";
        let result = falcon_verify(&pubkey, &sig, wrong_msg).expect("verify should not error");
        assert!(!result, "signature should NOT verify with wrong message");
    }

    #[test]
    fn test_verify_wrong_pubkey() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (_, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let seed2 = [1u8; FALCON_SEED_SIZE];
        let (pubkey2, _) = falcon_keygen(&seed2).expect("keygen should succeed");

        let msg = b"test message";
        let sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        let result = falcon_verify(&pubkey2, &sig, msg).expect("verify should not error");
        assert!(!result, "signature should NOT verify with wrong pubkey");
    }

    #[test]
    fn test_deterministic_signatures() {
        let seed = [42u8; FALCON_SEED_SIZE];
        let (_, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let msg = b"deterministic signing test";
        let sig1 = falcon_sign(&privkey, msg).expect("sign should succeed");
        let sig2 = falcon_sign(&privkey, msg).expect("sign should succeed");

        assert_eq!(sig1, sig2, "deterministic signatures should be identical");
    }

    #[test]
    fn test_verify_empty_message() {
        let seed = [7u8; FALCON_SEED_SIZE];
        let (pubkey, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let msg = b"";
        let sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        let result = falcon_verify(&pubkey, &sig, msg).expect("verify should not error");
        assert!(result, "empty message signature should verify");
    }

    #[test]
    fn test_invalid_pubkey_size() {
        let bad_pk = vec![0u8; 100];
        let sig = vec![0u8; 100];
        let msg = b"test";

        let err = falcon_verify(&bad_pk, &sig, msg).unwrap_err();
        assert!(matches!(err, FalconError::InvalidPubkeySize(100)));
    }

    #[test]
    fn test_invalid_signature_empty() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, _) = falcon_keygen(&seed).expect("keygen should succeed");

        let empty_sig: &[u8] = &[];
        let msg = b"test";

        let err = falcon_verify(&pubkey, empty_sig, msg).unwrap_err();
        assert!(matches!(err, FalconError::InvalidSignatureSize(0)));
    }

    #[test]
    fn test_invalid_signature_one_byte() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, _) = falcon_keygen(&seed).expect("keygen should succeed");

        let one_byte_sig: &[u8] = &[0xBA];
        let msg = b"test";

        let err = falcon_verify(&pubkey, one_byte_sig, msg).unwrap_err();
        assert!(matches!(err, FalconError::InvalidSignatureSize(1)));
    }

    /// Port of the "signature" subtest of go's
    /// `TestTxnValidationPQSigRejectsMalformedProof`
    /// (`data/transactions/verify/txn_test.go`): a signature blob larger than
    /// `crypto.MaxPQSignatureSize` must be rejected on a cheap length check
    /// before any FFI verification call, not just an undersized one (already
    /// covered by `test_invalid_signature_empty`/`test_invalid_signature_one_byte`).
    #[test]
    fn test_invalid_signature_oversized() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, _) = falcon_keygen(&seed).expect("keygen should succeed");

        let oversized_sig = vec![0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE + 1];
        let msg = b"test";

        let err = falcon_verify(&pubkey, &oversized_sig, msg).unwrap_err();
        assert!(matches!(
            err,
            FalconError::InvalidSignatureSize(n) if n == FALCON_DET1024_SIG_COMPRESSED_MAXSIZE + 1
        ));
    }

    // ── Phase 17 missing-test sweep (batch 6, docs/phase17/parity_crypto.md) ──

    #[test]
    fn test_falcon_convert_compressed_to_ct_differs_from_compressed_and_is_deterministic() {
        // TestFalconsFormatConversion (crypto/falconWrapper_test.go): the
        // fixed-width "CT" conversion of a compressed signature must be
        // deterministic and distinct from the original compressed encoding.
        let seed = [5u8; FALCON_SEED_SIZE];
        let (_, privkey) = falcon_keygen(&seed).expect("keygen should succeed");
        let msg = b"Neque porro quisquam est qui dolorem ipsum quia dolor sit amet";
        let sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        let ct1 = falcon_convert_compressed_to_ct(&sig).expect("conversion should succeed");
        let ct2 = falcon_convert_compressed_to_ct(&sig).expect("conversion should succeed");
        assert_eq!(ct1, ct2, "CT conversion must be deterministic");
        assert_eq!(ct1.len(), FALCON_DET1024_SIG_CT_SIZE);

        assert_ne!(
            sig.as_slice(),
            &ct1[..],
            "compressed and CT forms are different byte encodings of the same signature"
        );
    }

    #[test]
    fn test_falcon_salt_version_matches_current_then_diverges_on_corruption() {
        // TestFalconSignature_ValidateVersion (crypto/falconWrapper_test.go):
        // a freshly produced signature carries the current salt version;
        // corrupting the salt-version byte changes what's parsed back.
        let seed = [3u8; FALCON_SEED_SIZE];
        let (_, privkey) = falcon_keygen(&seed).expect("keygen should succeed");
        let msg = b"Neque porro quisquam est qui dolorem ipsum quia dolor sit amet";
        let mut sig = falcon_sign(&privkey, msg).expect("sign should succeed");

        let version = falcon_salt_version(&sig).expect("salt version should be extractable");
        // MERKLE_SIGNATURE_SCHEME_SALT_VERSION (algo-consensus-crypto's
        // stateproof.rs) is pinned to 0, matching go-algorand's
        // falcon.CurrentSaltVersion -- mirror that same expectation here at
        // the FFI layer.
        assert_eq!(
            version, 0,
            "freshly produced signature should carry the current salt version"
        );

        sig[1] = sig[1].wrapping_add(1);
        let corrupted_version =
            falcon_salt_version(&sig).expect("corrupted sig salt byte should still parse");
        assert_ne!(
            corrupted_version, version,
            "corrupting the salt-version byte must change the parsed version"
        );
    }

    /// Pins the seed size to go-algorand's post-`569ae3d4b` value.
    ///
    /// Upstream (`crypto/falconWrapper.go`): `FalconSeedSize` was changed from
    /// 48 to 32 bytes -- genuine 256-bit entropy for keygen-from-seed, not the
    /// old value inherited from falcon.c's SHAKE256 explicit-seed API. See
    /// go-algorand issue-referenced commit `569ae3d4b` ("txn: native PQ
    /// accounts (#6639)").
    #[test]
    fn test_falcon_seed_size_is_32_bytes_matching_go_algorand_post_569ae3d4b() {
        assert_eq!(
            FALCON_SEED_SIZE, 32,
            "FALCON_SEED_SIZE must match go-algorand's crypto.FalconSeedSize (32), \
             not the old pre-569ae3d4b value of 48"
        );
    }

    /// Pins that `falcon_sign`/`falcon_verify` operate on exactly the bytes
    /// the caller supplies, with no internal re-hashing layer.
    ///
    /// This is the byte-level primitive that go-algorand's `SignBytes`/
    /// `VerifyBytes` map onto directly (both before and after commit
    /// `48c92817b`, "falcon: sign ToBeHashed, not Hashed" -- that fix only
    /// touched the higher-level `Sign(Hashable)`/`Verify(Hashable)`
    /// convenience wrappers, which double-hashed via `Hash(HashRep(message))`
    /// before handing bytes to `SignBytes`). algod-rust never implements
    /// those higher-level wrappers -- every call site in this codebase
    /// (state-proof signing/verification, the MSS ephemeral-key scheme, the
    /// `falcon_verify` AVM opcode) calls straight through to these byte-level
    /// primitives with the caller's own message bytes. A signature produced
    /// over `msg` must therefore NOT verify against `sha256(msg)` (the old,
    /// double-hashed convention) and vice versa -- proving no hidden hash
    /// step is applied on either side.
    #[test]
    fn test_sign_verify_operate_on_raw_bytes_not_a_rehash() {
        let seed = [3u8; FALCON_SEED_SIZE];
        let (pubkey, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let msg = b"ToBeHashed-style domain-separated message bytes";
        let old_convention_digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(msg);
            hasher.finalize().to_vec()
        };
        assert_ne!(
            msg.as_slice(),
            old_convention_digest.as_slice(),
            "test setup: digest must actually differ from the raw message"
        );

        // New (correct) convention: sign the raw message bytes directly.
        let sig_over_raw = falcon_sign(&privkey, msg).expect("sign should succeed");
        assert!(
            falcon_verify(&pubkey, &sig_over_raw, msg).expect("verify should not error"),
            "signature over raw message bytes must verify against those same raw bytes"
        );
        assert!(
            !falcon_verify(&pubkey, &sig_over_raw, &old_convention_digest)
                .expect("verify should not error"),
            "a signature over raw bytes must NOT verify against sha256(raw bytes) -- \
             that would mean we're silently accepting the old double-hashed convention"
        );

        // Old (buggy, pre-48c92817b) convention: sign a hash of the message.
        let sig_over_digest =
            falcon_sign(&privkey, &old_convention_digest).expect("sign should succeed");
        assert!(
            !falcon_verify(&pubkey, &sig_over_digest, msg).expect("verify should not error"),
            "a signature over sha256(raw bytes) must NOT verify against the raw bytes \
             themselves -- the two conventions must not be interchangeable"
        );
    }

    #[test]
    fn test_go_algorand_test_vector() {
        let seed = [0u8; FALCON_SEED_SIZE];
        let (pubkey, privkey) = falcon_keygen(&seed).expect("keygen should succeed");

        let msg = hex_decode("62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd");
        let sig = falcon_sign(&privkey, &msg).expect("sign should succeed");

        let result = falcon_verify(&pubkey, &sig, &msg).expect("verify should not error");
        assert!(result, "go-algorand test vector should verify");
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
