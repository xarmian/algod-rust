//! Re-exports from the `algo-falcon` crate.
//!
//! The Falcon FFI bindings and safe wrappers now live in the shared
//! `algo-falcon` crate so that both `algo-avm` and `algo-consensus-crypto`
//! can use them.

pub use algo_falcon::{
    falcon_keygen, falcon_sign, falcon_verify, FalconError, FALCON_DET1024_PRIVKEY_SIZE,
    FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_SIG_CT_SIZE,
    FALCON_SEED_SIZE,
};

// ---------------------------------------------------------------------------
// Tests — kept here to verify the re-export path works identically.
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

    use super::super::hex_decode;
}
