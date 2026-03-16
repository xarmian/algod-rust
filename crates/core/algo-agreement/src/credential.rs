// Credential types matching go-algorand/data/committee/credential.go.
//
// UnauthenticatedCredential holds a VRF proof that can be verified against
// a Membership to produce a Credential with a sortition weight.

use algo_consensus_crypto::sortition;
use algo_consensus_crypto::vrf::VrfPubkey;
use algo_types::{Address, ConsensusParams, Digest};
use num_bigint::BigUint;
use sha2::{Digest as _, Sha512_256};

use crate::hashable::{hash_obj, hash_rep, Hashable};
use crate::Selector;
use crate::VRF_PROOF_SIZE;
/// Size of a VRF output in bytes.
const VRF_OUTPUT_SIZE: usize = 64;

/// An unauthenticated credential — a VRF proof that has not yet been verified.
///
/// Mirrors Go's `committee.UnauthenticatedCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthenticatedCredential {
    /// The VRF proof bytes (80 bytes).
    pub proof: [u8; VRF_PROOF_SIZE],
}

impl UnauthenticatedCredential {
    /// Create a new unauthenticated credential from a VRF proof.
    pub fn new(proof: [u8; VRF_PROOF_SIZE]) -> Self {
        Self { proof }
    }

    /// Verify this credential against the given membership and consensus params.
    ///
    /// On success, returns a `Credential` with the computed sortition weight.
    /// Returns an error if VRF verification fails or the weight is zero.
    ///
    /// Mirrors Go's `UnauthenticatedCredential.Verify()`.
    pub fn verify(
        &self,
        params: &ConsensusParams,
        membership: &Membership,
    ) -> Result<Credential, CredentialError> {
        let vrf_pk = VrfPubkey::from_bytes(membership.selection_id);

        // Build the VRF message: hash_rep(selector) = "AS" || encode(selector)
        // Go passes HashRep(selector) (raw domain-separated bytes, NOT the digest)
        let vrf_message = hash_rep(&membership.selector);

        // Verify VRF proof
        let vrf_proof = algo_consensus_crypto::vrf::VrfProof(self.proof);
        let vrf_out = vrf_pk
            .verify(&vrf_proof, &vrf_message)
            .ok_or(CredentialError::VrfVerificationFailed)?;

        let hashable = HashableCredential {
            raw_out: vrf_out.0,
            member: membership.address,
            iter: 0,
        };

        // Compute the hash for sortition — with or without domain separation
        let h = if params.credential_domain_separation_enabled {
            hash_obj(&hashable)
        } else {
            // Legacy path: SHA512/256(vrf_output || address)
            let mut data = Vec::with_capacity(VRF_OUTPUT_SIZE + 32);
            data.extend_from_slice(&vrf_out.0);
            data.extend_from_slice(&membership.address.0);
            let result = Sha512_256::digest(&data);
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            Digest(out)
        };

        // Compute sortition weight
        let expected_selection =
            membership.selector.committee_size(params) as f64;

        if membership.total_money == 0 || expected_selection == 0.0 {
            return Err(CredentialError::InvalidParameters);
        }

        if membership.total_money < membership.balance {
            return Err(CredentialError::InvalidParameters);
        }

        let weight = if membership.balance == 0 {
            0
        } else {
            sortition::select(
                membership.balance,
                membership.total_money,
                expected_selection,
                h.0,
            )
        };

        if weight == 0 {
            return Err(CredentialError::ZeroWeight);
        }

        let mut cred = Credential {
            weight,
            vrf_out: h,
            domain_separation_enabled: params.credential_domain_separation_enabled,
            hashable: HashableCredential::default(),
            proof: self.proof,
        };

        if cred.domain_separation_enabled {
            cred.hashable = hashable;
        }

        Ok(cred)
    }
}

/// A verified credential with computed sortition weight.
///
/// Mirrors Go's `committee.Credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The number of sub-committee seats won.
    pub weight: u64,
    /// The VRF output hash (with address mixed in), used for sortition.
    pub vrf_out: Digest,
    /// Whether domain separation was enabled when this credential was created.
    pub domain_separation_enabled: bool,
    /// The hashable credential (only populated when domain separation is enabled).
    pub hashable: HashableCredential,
    /// The original VRF proof bytes.
    pub proof: [u8; VRF_PROOF_SIZE],
}

impl Credential {
    /// Returns whether this credential was selected (weight > 0).
    pub fn selected(&self) -> bool {
        self.weight > 0
    }

    /// Returns true if this credential's VRF output equals another's.
    pub fn equals(&self, other: &Credential) -> bool {
        self.vrf_out == other.vrf_out
    }

    /// Returns true if this credential should be preferred over `other` for
    /// proposal tiebreaking (lower output wins).
    ///
    /// Precondition: both credentials have nonzero weight.
    pub fn less(&self, other: &Credential) -> bool {
        let i1 = self.lowest_output();
        let i2 = other.lowest_output();
        i1 < i2
    }

    /// Compute the lowest output for proposal tiebreaking.
    ///
    /// For credentials with weight w > 1, we hash the credential w times
    /// (with different counter values starting from 1) and use the lowest.
    ///
    /// Mirrors Go's `Credential.lowestOutput()`.
    pub fn lowest_output(&self) -> BigUint {
        let mut lowest: Option<BigUint> = None;

        let h1 = self.vrf_out;

        // Important: i starts at 1 (not 0) to provide domain separation
        // between lowestOutput and UnauthenticatedCredential.Verify
        for i in 1..=self.weight {
            let h = if self.domain_separation_enabled {
                let mut hc = self.hashable.clone();
                hc.iter = i;
                hash_obj(&hc)
            } else {
                // Legacy path: SHA512/256(h1 || big-endian-u64(i))
                let mut h2 = [0u8; 32];
                h2[..8].copy_from_slice(&i.to_be_bytes());
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&h1.0);
                data.extend_from_slice(&h2);
                let result = Sha512_256::digest(&data);
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                Digest(out)
            };

            let val = BigUint::from_bytes_be(&h.0);
            lowest = Some(match lowest {
                None => val,
                Some(prev) => {
                    if val < prev {
                        val
                    } else {
                        prev
                    }
                }
            });
        }

        lowest.unwrap_or_default()
    }

    /// Returns the lowestOutput as a Digest (for debugging/display).
    pub fn lowest_output_digest(&self) -> Digest {
        let lo = self.lowest_output();
        let lo_bytes = lo.to_bytes_be();
        let mut out = [0u8; 32];
        if lo_bytes.len() <= 32 {
            // Right-align the bytes in the digest
            out[32 - lo_bytes.len()..].copy_from_slice(&lo_bytes);
        }
        Digest(out)
    }
}

/// The hashable form of a credential, used for domain-separated hashing.
///
/// Mirrors Go's `hashableCredential` struct.
///
/// Msgpack field order (alphabetical by codec tag, omitempty):
///   "i" -> Iter (uint64)
///   "m" -> Member (Address, 32 bytes)
///   "v" -> RawOut (VrfOutput, 64 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashableCredential {
    /// Raw VRF output (64 bytes).
    pub raw_out: [u8; VRF_OUTPUT_SIZE],
    /// Account address.
    pub member: Address,
    /// Iteration counter (used in lowestOutput tiebreaking).
    pub iter: u64,
}

impl Default for HashableCredential {
    fn default() -> Self {
        Self {
            raw_out: [0u8; VRF_OUTPUT_SIZE],
            member: Address([0u8; 32]),
            iter: 0,
        }
    }
}

/// Canonical msgpack encoding of a `HashableCredential`, matching Go's
/// generated `hashableCredential.MarshalMsg`.
///
/// Fields in alphabetical order by codec tag (omitempty):
///   "i" -> Iter
///   "m" -> Member
///   "v" -> RawOut
fn encode_hashable_credential(hc: &HashableCredential) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // Count non-empty fields for the map header
    let mut count: u8 = 0;
    let iter_empty = hc.iter == 0;
    let member_empty = hc.member.0 == [0u8; 32];
    let raw_out_empty = hc.raw_out == [0u8; VRF_OUTPUT_SIZE];

    if !iter_empty {
        count += 1;
    }
    if !member_empty {
        count += 1;
    }
    if !raw_out_empty {
        count += 1;
    }

    // fixmap header
    buf.push(0x80 | count);

    if count == 0 {
        return buf;
    }

    // "i" -> Iter
    if !iter_empty {
        buf.extend_from_slice(&[0xa1, b'i']);
        rmp::encode::write_uint(&mut buf, hc.iter).unwrap();
    }

    // "m" -> Member (32-byte address encoded as bin)
    if !member_empty {
        buf.extend_from_slice(&[0xa1, b'm']);
        rmp::encode::write_bin(&mut buf, &hc.member.0).unwrap();
    }

    // "v" -> RawOut (64-byte VRF output encoded as bin)
    if !raw_out_empty {
        buf.extend_from_slice(&[0xa1, b'v']);
        rmp::encode::write_bin(&mut buf, &hc.raw_out).unwrap();
    }

    buf
}

impl Hashable for HashableCredential {
    /// HashID = `"CR"` (protocol.Credential).
    fn hash_id() -> &'static [u8] {
        b"CR"
    }

    fn to_be_hashed(&self) -> Vec<u8> {
        encode_hashable_credential(self)
    }
}

/// Membership encodes the parameters used to verify committee membership.
///
/// Mirrors Go's `committee.Membership`, but flattened from the Go structure
/// (which embeds `BalanceRecord` containing `OnlineAccountData` and `Addr`).
#[derive(Debug, Clone)]
pub struct Membership {
    /// The account's address.
    pub address: Address,
    /// The VRF selection public key (32 bytes, from OnlineAccountData.SelectionID).
    pub selection_id: [u8; 32],
    /// The account's voting stake (microAlgos).
    pub balance: u64,
    /// The total online stake (microAlgos).
    pub total_money: u64,
    /// The selector defining which committee we're checking membership in.
    pub selector: Selector,
}

/// Errors that can occur during credential verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// VRF proof verification failed.
    VrfVerificationFailed,
    /// The computed sortition weight is zero (not selected).
    ZeroWeight,
    /// Invalid parameters (e.g. total_money < balance, or zero total/expected).
    InvalidParameters,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VrfVerificationFailed => write!(f, "VRF proof verification failed"),
            Self::ZeroWeight => write!(f, "credential has weight 0"),
            Self::InvalidParameters => write!(f, "invalid membership parameters"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;
    use crate::step::{Period, Step, PROPOSE, SOFT};
    use algo_consensus_crypto::vrf::VrfKeypair;
    use algo_types::consensus::consensus_params_for_version;
    use algo_types::Round;

    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::CONSENSUS_V41).expect("v41 params")
    }

    fn v7_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::consensus::CONSENSUS_V7).expect("v7 params")
    }

    // ---- HashableCredential encoding tests ----

    #[test]
    fn hashable_credential_hash_id_is_cr() {
        assert_eq!(HashableCredential::hash_id(), b"CR");
    }

    #[test]
    fn hashable_credential_empty_encodes_to_empty_map() {
        let hc = HashableCredential::default();
        let encoded = encode_hashable_credential(&hc);
        // Empty map: fixmap(0) = 0x80
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn hashable_credential_field_order() {
        let hc = HashableCredential {
            raw_out: [0xff; VRF_OUTPUT_SIZE],
            member: Address([0xaa; 32]),
            iter: 42,
        };
        let encoded = encode_hashable_credential(&hc);

        // fixmap(3)
        assert_eq!(encoded[0], 0x83);

        // Find field positions
        let encoded_str = String::from_utf8_lossy(&encoded);
        let i_pos = encoded_str.find('i').unwrap();
        let m_pos = encoded_str.find('m').unwrap();
        let v_pos = encoded_str.find('v').unwrap();

        assert!(i_pos < m_pos, "i must come before m");
        assert!(m_pos < v_pos, "m must come before v");
    }

    #[test]
    fn hashable_credential_omitempty_iter_zero() {
        let hc = HashableCredential {
            raw_out: [0xff; VRF_OUTPUT_SIZE],
            member: Address([0xaa; 32]),
            iter: 0,
        };
        let encoded = encode_hashable_credential(&hc);
        // fixmap(2) — iter omitted
        assert_eq!(encoded[0], 0x82);
    }

    #[test]
    fn hashable_credential_omitempty_member_zero() {
        let hc = HashableCredential {
            raw_out: [0xff; VRF_OUTPUT_SIZE],
            member: Address([0x00; 32]),
            iter: 1,
        };
        let encoded = encode_hashable_credential(&hc);
        // fixmap(2) — member omitted
        assert_eq!(encoded[0], 0x82);
    }

    #[test]
    fn hashable_credential_hash_obj_deterministic() {
        let hc = HashableCredential {
            raw_out: [0x42; VRF_OUTPUT_SIZE],
            member: Address([0x01; 32]),
            iter: 5,
        };
        let d1 = hash_obj(&hc);
        let d2 = hash_obj(&hc);
        assert_eq!(d1, d2);
    }

    #[test]
    fn hashable_credential_different_iter_different_hash() {
        let hc1 = HashableCredential {
            raw_out: [0x42; VRF_OUTPUT_SIZE],
            member: Address([0x01; 32]),
            iter: 1,
        };
        let hc2 = HashableCredential {
            raw_out: [0x42; VRF_OUTPUT_SIZE],
            member: Address([0x01; 32]),
            iter: 2,
        };
        assert_ne!(hash_obj(&hc1), hash_obj(&hc2));
    }

    // ---- Membership construction tests ----

    #[test]
    fn membership_construction() {
        let kp = VrfKeypair::from_seed([1u8; 32]);
        let m = Membership {
            address: Address([0x42; 32]),
            selection_id: *kp.pk.as_bytes(),
            balance: 1_000_000,
            total_money: 10_000_000,
            selector: Selector {
                seed: Seed::default(),
                round: Round(100),
                period: Period(0),
                step: SOFT,
            },
        };
        assert_eq!(m.balance, 1_000_000);
        assert_eq!(m.total_money, 10_000_000);
        assert_eq!(m.address, Address([0x42; 32]));
    }

    // ---- VRF verification flow tests ----

    fn make_test_membership(kp: &VrfKeypair, step: Step, balance: u64, total: u64) -> Membership {
        Membership {
            address: Address([0x42; 32]),
            selection_id: *kp.pk.as_bytes(),
            balance,
            total_money: total,
            selector: Selector {
                seed: Seed([0xab; 32]),
                round: Round(100),
                period: Period(0),
                step,
            },
        }
    }

    fn make_unauthenticated_credential(
        kp: &VrfKeypair,
        selector: &Selector,
    ) -> UnauthenticatedCredential {
        let vrf_message = hash_rep(selector);
        let (proof, _) = kp.sk.prove(&vrf_message);
        UnauthenticatedCredential::new(*proof.as_bytes())
    }

    #[test]
    fn verify_valid_credential_with_domain_separation() {
        let params = v41_params();
        assert!(params.credential_domain_separation_enabled);

        let kp = VrfKeypair::from_seed([7u8; 32]);
        // Use large balance relative to total so we're very likely selected
        let membership = make_test_membership(&kp, PROPOSE, 5_000_000, 10_000_000);
        let ucred = make_unauthenticated_credential(&kp, &membership.selector);

        // The credential may or may not be selected depending on VRF output.
        // We just check the verify flow doesn't panic and returns a well-formed result.
        let result = ucred.verify(&params, &membership);
        match result {
            Ok(cred) => {
                assert!(cred.weight > 0);
                assert!(cred.selected());
                assert!(cred.domain_separation_enabled);
            }
            Err(CredentialError::ZeroWeight) => {
                // This is valid — the VRF output just didn't select us
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn verify_valid_credential_without_domain_separation() {
        let params = v7_params();
        assert!(!params.credential_domain_separation_enabled);

        let kp = VrfKeypair::from_seed([7u8; 32]);
        let membership = make_test_membership(&kp, PROPOSE, 5_000_000, 10_000_000);
        let ucred = make_unauthenticated_credential(&kp, &membership.selector);

        let result = ucred.verify(&params, &membership);
        match result {
            Ok(cred) => {
                assert!(cred.weight > 0);
                assert!(!cred.domain_separation_enabled);
            }
            Err(CredentialError::ZeroWeight) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let params = v41_params();
        let kp = VrfKeypair::from_seed([7u8; 32]);
        let wrong_kp = VrfKeypair::from_seed([8u8; 32]);

        let membership = make_test_membership(&kp, SOFT, 5_000_000, 10_000_000);

        // Create credential with the wrong key
        let ucred = make_unauthenticated_credential(&wrong_kp, &membership.selector);

        let result = ucred.verify(&params, &membership);
        assert_eq!(result, Err(CredentialError::VrfVerificationFailed));
    }

    #[test]
    fn verify_fails_with_corrupted_proof() {
        let params = v41_params();
        let kp = VrfKeypair::from_seed([7u8; 32]);
        let membership = make_test_membership(&kp, SOFT, 5_000_000, 10_000_000);
        let mut ucred = make_unauthenticated_credential(&kp, &membership.selector);

        // Corrupt the proof
        ucred.proof[10] ^= 0xff;

        let result = ucred.verify(&params, &membership);
        assert_eq!(result, Err(CredentialError::VrfVerificationFailed));
    }

    #[test]
    fn verify_zero_balance_gives_zero_weight() {
        let params = v41_params();
        let kp = VrfKeypair::from_seed([7u8; 32]);
        let membership = make_test_membership(&kp, SOFT, 0, 10_000_000);
        let ucred = make_unauthenticated_credential(&kp, &membership.selector);

        let result = ucred.verify(&params, &membership);
        assert_eq!(result, Err(CredentialError::ZeroWeight));
    }

    // ---- lowest_output tests ----

    #[test]
    fn lowest_output_weight_one() {
        // With weight 1, lowest_output should just be hash(iter=1)
        let cred = Credential {
            weight: 1,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential {
                raw_out: [0x42; VRF_OUTPUT_SIZE],
                member: Address([0x01; 32]),
                iter: 0,
            },
            proof: [0; VRF_PROOF_SIZE],
        };

        let lo = cred.lowest_output();
        // Should be non-zero
        assert!(lo > BigUint::from(0u32));
    }

    #[test]
    fn lowest_output_weight_two_le_weight_one() {
        // With weight 2, the lowest output should be <= weight 1's output
        // (since we pick the minimum of two hashes)
        let hc = HashableCredential {
            raw_out: [0x42; VRF_OUTPUT_SIZE],
            member: Address([0x01; 32]),
            iter: 0,
        };

        let cred1 = Credential {
            weight: 1,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: true,
            hashable: hc.clone(),
            proof: [0; VRF_PROOF_SIZE],
        };

        let cred2 = Credential {
            weight: 2,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: true,
            hashable: hc,
            proof: [0; VRF_PROOF_SIZE],
        };

        assert!(cred2.lowest_output() <= cred1.lowest_output());
    }

    #[test]
    fn lowest_output_legacy_no_domain_separation() {
        let cred = Credential {
            weight: 1,
            vrf_out: Digest([0xbb; 32]),
            domain_separation_enabled: false,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        let lo = cred.lowest_output();
        assert!(lo > BigUint::from(0u32));

        // Verify it matches the expected computation:
        // SHA512/256(vrf_out || big_endian(1))
        let mut h2 = [0u8; 32];
        h2[..8].copy_from_slice(&1u64.to_be_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&[0xbb; 32]);
        data.extend_from_slice(&h2);
        let expected = Sha512_256::digest(&data);
        let expected_int = BigUint::from_bytes_be(&expected);
        assert_eq!(lo, expected_int);
    }

    #[test]
    fn lowest_output_digest_roundtrip() {
        let cred = Credential {
            weight: 1,
            vrf_out: Digest([0xcc; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential {
                raw_out: [0x11; VRF_OUTPUT_SIZE],
                member: Address([0x22; 32]),
                iter: 0,
            },
            proof: [0; VRF_PROOF_SIZE],
        };

        let digest = cred.lowest_output_digest();
        let lo = cred.lowest_output();
        let lo_bytes = lo.to_bytes_be();

        // The digest should contain the lowestOutput bytes right-aligned
        assert_eq!(&digest.0[32 - lo_bytes.len()..], &lo_bytes);
    }

    #[test]
    fn credential_less_comparison() {
        // Create two credentials with different VRF outputs — one will be "less"
        let cred_a = Credential {
            weight: 1,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: false,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        let cred_b = Credential {
            weight: 1,
            vrf_out: Digest([0xbb; 32]),
            domain_separation_enabled: false,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        // Exactly one of these should be true (they can't be equal since
        // different vrf_out values will produce different lowestOutput)
        let a_less_b = cred_a.less(&cred_b);
        let b_less_a = cred_b.less(&cred_a);
        assert_ne!(a_less_b, b_less_a, "one must be less than the other");
    }

    #[test]
    fn credential_equals() {
        let cred_a = Credential {
            weight: 1,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        let cred_b = Credential {
            weight: 2,
            vrf_out: Digest([0xaa; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        let cred_c = Credential {
            weight: 1,
            vrf_out: Digest([0xbb; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };

        assert!(cred_a.equals(&cred_b), "same vrf_out should be equal");
        assert!(!cred_a.equals(&cred_c), "different vrf_out should not be equal");
    }

    #[test]
    fn credential_selected() {
        let cred = Credential {
            weight: 3,
            vrf_out: Digest([0; 32]),
            domain_separation_enabled: true,
            hashable: HashableCredential::default(),
            proof: [0; VRF_PROOF_SIZE],
        };
        assert!(cred.selected());
    }

    // ---- End-to-end test with real VRF ----

    #[test]
    fn end_to_end_prove_verify_credential() {
        // This test creates a VRF keypair, constructs a credential, and verifies it.
        // We use PROPOSE step with a large stake fraction to maximize selection probability.
        let params = v41_params();
        let kp = VrfKeypair::from_seed([42u8; 32]);

        // Try multiple seeds to find one where we get selected
        let mut found_selected = false;
        for seed_byte in 0..100u8 {
            let membership = Membership {
                address: Address([seed_byte; 32]),
                selection_id: *kp.pk.as_bytes(),
                balance: 9_000_000,   // 90% of total
                total_money: 10_000_000,
                selector: Selector {
                    seed: Seed([seed_byte; 32]),
                    round: Round(100),
                    period: Period(0),
                    step: PROPOSE,
                },
            };

            let ucred = make_unauthenticated_credential(&kp, &membership.selector);

            if let Ok(cred) = ucred.verify(&params, &membership) {
                found_selected = true;
                assert!(cred.weight > 0);
                assert!(cred.selected());
                assert!(cred.domain_separation_enabled);
                // lowest_output should be computable without panic
                let _ = cred.lowest_output();
                let _ = cred.lowest_output_digest();
                break;
            }
        }
        assert!(found_selected, "should have found at least one selected credential in 100 tries with 90% stake");
    }
}
