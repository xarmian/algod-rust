//! FFI bindings and safe Rust wrappers for the Algorand deterministic Falcon-1024
//! C library (github.com/algorand/falcon v0.1.0).
//!
//! **Important**: This is Algorand's custom *deterministic* Falcon-1024, NOT the
//! standard NIST Falcon submission. Key differences from standard Falcon:
//!
//! - Signing is fully deterministic (no random salt/nonce).
//! - Wire format replaces the 40-byte salt with a 1-byte salt version
//!   (currently version 0), reducing signature overhead.
//! - Custom header byte `0xBA` (compressed format: `0x3A | 0x80`) instead of
//!   the standard Falcon compressed header, signalling deterministic mode.
//! - Uses emulated floating-point (`FALCON_FPEMU=1`) to guarantee cross-platform
//!   determinism.
//!
//! Wire format sizes:
//! - Public key: 1793 bytes
//! - Max compressed signature: 1423 bytes (variable-length; actual sigs are shorter)
//! - Private key: 2305 bytes (not used on-chain, only for signing)
//!
//! Only the compressed-format deterministic variant is used on-chain.
//! The library is compiled from vendored C sources in `falcon-c/`.

use std::os::raw::{c_int, c_void};

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

/// Seed size used for deterministic key generation.
pub const FALCON_SEED_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Internal types and FFI
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Safe Rust wrappers
// ---------------------------------------------------------------------------

/// Verify a deterministic Falcon-1024 compressed-format signature.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if verification
/// fails (bad signature), or `Err` if the inputs are malformed (wrong sizes).
pub fn falcon_verify(pubkey: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, FalconError> {
    if pubkey.len() != FALCON_DET1024_PUBKEY_SIZE {
        return Err(FalconError::InvalidPubkeySize(pubkey.len()));
    }
    if sig.len() < 2 || sig.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
        return Err(FalconError::InvalidSignatureSize(sig.len()));
    }

    let data_ptr = if data.is_empty() {
        std::ptr::null()
    } else {
        data.as_ptr() as *const c_void
    };

    let rc = unsafe {
        falcon_det1024_verify_compressed(
            sig.as_ptr() as *const c_void,
            sig.len(),
            pubkey.as_ptr() as *const c_void,
            data_ptr,
            data.len(),
        )
    };

    Ok(rc == 0)
}

/// Generate a Falcon-1024 keypair from the given seed.
///
/// The seed is used to initialize a SHAKE256 PRNG, producing deterministic keys
/// for a given seed value. Use a cryptographically random seed in production.
pub fn falcon_keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    let mut rng = Shake256Context {
        opaque_contents: [0u64; SHAKE256_CONTEXT_SIZE],
    };

    let seed_ptr = if seed.is_empty() {
        std::ptr::null()
    } else {
        seed.as_ptr() as *const c_void
    };

    unsafe {
        shake256_init_prng_from_seed(&mut rng, seed_ptr, seed.len());
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

/// Sign data with a Falcon-1024 private key, producing a compressed-format
/// deterministic signature.
pub fn falcon_sign(privkey: &[u8], data: &[u8]) -> Result<Vec<u8>, FalconError> {
    if privkey.len() != FALCON_DET1024_PRIVKEY_SIZE {
        return Err(FalconError::InvalidPrivkeySize(privkey.len()));
    }

    let mut sig = vec![0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
    let mut sig_len: usize = FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;

    let data_ptr = if data.is_empty() {
        std::ptr::null()
    } else {
        data.as_ptr() as *const c_void
    };

    let rc = unsafe {
        falcon_det1024_sign_compressed(
            sig.as_mut_ptr() as *mut c_void,
            &mut sig_len,
            privkey.as_ptr() as *const c_void,
            data_ptr,
            data.len(),
        )
    };

    if rc != 0 {
        return Err(FalconError::SignFailed(rc));
    }

    sig.truncate(sig_len);
    Ok(sig)
}

/// Convert a compressed-format deterministic Falcon-1024 signature to the
/// fixed-width "CT" (constant-time-decodable) representation.
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
    if sig_compressed.len() < 2 || sig_compressed.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
        return Err(FalconError::InvalidSignatureSize(sig_compressed.len()));
    }

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

/// Return the salt version embedded in a Falcon signature (compressed or CT
/// form), matching go-algorand's `crypto.FalconSignature.IsSaltVersionEqual`
/// (`crypto/falconWrapper.go:127`), which compares this value against an
/// expected version.
pub fn falcon_salt_version(sig: &[u8]) -> Result<u8, FalconError> {
    if sig.is_empty() {
        return Err(FalconError::InvalidSignatureSize(0));
    }
    let rc = unsafe { falcon_det1024_get_salt_version(sig.as_ptr() as *const c_void) };
    if rc < 0 {
        return Err(FalconError::SaltVersionFailed(rc));
    }
    Ok(rc as u8)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the Falcon FFI layer.
#[derive(Debug, Clone)]
pub enum FalconError {
    /// Public key has wrong length (expected 1793 bytes).
    InvalidPubkeySize(usize),
    /// Private key has wrong length (expected 2305 bytes).
    InvalidPrivkeySize(usize),
    /// Signature has invalid length (must be 2..=1423 bytes).
    InvalidSignatureSize(usize),
    /// Key generation returned a non-zero error code.
    KeygenFailed(c_int),
    /// Signing returned a non-zero error code.
    SignFailed(c_int),
    /// Compressed-to-CT conversion returned a non-zero error code.
    ConvertToCtFailed(c_int),
    /// Salt-version extraction returned a negative error code.
    SaltVersionFailed(c_int),
}

impl std::fmt::Display for FalconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        }
    }
}

impl std::error::Error for FalconError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
