//! VRF verify implementation: ECVRF-ED25519-SHA512-Elligator2 (draft-irtf-cfrg-vrf-03).
//!
//! The core VRF cryptographic primitives (field arithmetic, Elligator2 map,
//! hash-to-curve, proof verification) live in `algo-consensus-crypto::vrf`.
//! This module re-exports the `vrf_verify` function for use by the AVM opcode handler.

pub use algo_consensus_crypto::vrf::vrf_verify;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::vrf::{
        elligator2_ed25519, has_small_order, is_canonical_point_encoding, Fe25519,
    };
    use curve25519_dalek::edwards::CompressedEdwardsY;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Test vectors from draft-irtf-cfrg-vrf-03 appendix A.4 / go-algorand vrf_test.go.
    // Note: the "sk" in the test vectors is the 32-byte seed, not the 64-byte expanded key.
    // We only need pk, alpha, pi, and beta for verification.

    // Test vector 1: empty message
    const TV1_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TV1_ALPHA: &str = "";
    const TV1_PI: &str = "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900";
    const TV1_BETA: &str = "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc";

    // Test vector 2: message = 0x72
    const TV2_PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const TV2_ALPHA: &str = "72";
    const TV2_PI: &str = "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07";
    const TV2_BETA: &str = "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8";

    #[test]
    fn test_field_element_roundtrip() {
        let bytes = [0u8; 32];
        let fe = Fe25519::from_bytes(&bytes);
        assert_eq!(fe.to_bytes(), bytes);

        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let fe = Fe25519::from_bytes(&bytes);
        assert_eq!(fe.to_bytes(), bytes);
    }

    #[test]
    fn test_field_element_mul_identity() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        let fe = Fe25519::from_bytes(&bytes);
        let one = Fe25519::ONE;
        let result = fe.mul(&one);
        assert_eq!(result.to_bytes(), bytes);
    }

    #[test]
    fn test_field_element_invert() {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let fe = Fe25519::from_bytes(&bytes);
        let inv = fe.invert();
        let product = fe.mul(&inv);
        assert_eq!(product.to_bytes(), Fe25519::ONE.to_bytes());
    }

    #[test]
    fn test_is_canonical_valid() {
        // Identity point (0, 1)
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(is_canonical_point_encoding(&bytes));
    }

    #[test]
    fn test_is_canonical_invalid() {
        // p itself (not canonical)
        let bytes: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(!is_canonical_point_encoding(&bytes));
    }

    #[test]
    fn test_has_small_order_identity() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(has_small_order(&bytes));
    }

    #[test]
    fn test_has_small_order_normal_point() {
        // Ed25519 base point
        let basepoint = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        assert!(!has_small_order(&basepoint.to_bytes()));
    }

    #[test]
    fn test_vrf_verify_vector1() {
        let pk = hex_to_bytes(TV1_PK);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let pi = hex_to_bytes(TV1_PI);
        let expected_beta = hex_to_bytes(TV1_BETA);

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_some(),
            "VRF verify should succeed for test vector 1"
        );
        let output = result.unwrap();
        assert_eq!(
            output.to_vec(),
            expected_beta,
            "VRF output should match expected beta for test vector 1"
        );
    }

    #[test]
    fn test_vrf_verify_vector2() {
        let pk = hex_to_bytes(TV2_PK);
        let alpha = hex_to_bytes(TV2_ALPHA);
        let pi = hex_to_bytes(TV2_PI);
        let expected_beta = hex_to_bytes(TV2_BETA);

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_some(),
            "VRF verify should succeed for test vector 2"
        );
        let output = result.unwrap();
        assert_eq!(
            output.to_vec(),
            expected_beta,
            "VRF output should match expected beta for test vector 2"
        );
    }

    #[test]
    fn test_vrf_verify_invalid_proof() {
        let pk = hex_to_bytes(TV1_PK);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let mut pi = hex_to_bytes(TV1_PI);
        // Corrupt the proof
        pi[0] ^= 0xff;
        // The corrupted gamma may not even decompress, which is fine (returns None)

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail for corrupted proof"
        );
    }

    #[test]
    fn test_vrf_verify_wrong_pubkey() {
        let alpha = hex_to_bytes(TV1_ALPHA);
        let pi = hex_to_bytes(TV1_PI);
        // Use TV2's pubkey with TV1's proof
        let wrong_pk = hex_to_bytes(TV2_PK);

        let pk_arr: [u8; 32] = wrong_pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail with wrong public key"
        );
    }

    #[test]
    fn test_vrf_verify_wrong_message() {
        let pk = hex_to_bytes(TV2_PK);
        let pi = hex_to_bytes(TV2_PI);
        // Use wrong message (empty instead of 0x72)
        let wrong_alpha = b"";

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, wrong_alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail with wrong message"
        );
    }

    #[test]
    fn test_vrf_verify_zero_pubkey_rejected() {
        let pi = [0u8; 80];
        let pk = [0u8; 32]; // all zeros = small order
        let result = vrf_verify(&pk, &pi, b"test");
        assert!(
            result.is_none(),
            "VRF verify should reject zero public key (small order)"
        );
    }

    #[test]
    fn test_vrf_verify_zero_proof_zero_key_rejected() {
        // All-zero proof with valid-looking but non-matching key
        let pi = [0u8; 80];
        let pk = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let result = vrf_verify(&pk, &pi, b"test");
        assert!(result.is_none(), "VRF verify should fail with zero proof");
    }

    #[test]
    fn test_elligator2_deterministic() {
        // Same input should always produce same output
        let input = [42u8; 32];
        let out1 = elligator2_ed25519(&input);
        let out2 = elligator2_ed25519(&input);
        assert_eq!(out1, out2, "Elligator2 should be deterministic");
    }

    #[test]
    fn test_elligator2_output_is_valid_point() {
        let input = [42u8; 32];
        let out = elligator2_ed25519(&input);
        let compressed = CompressedEdwardsY(out);
        assert!(
            compressed.decompress().is_some(),
            "Elligator2 output should be a valid Edwards point"
        );
    }
}
