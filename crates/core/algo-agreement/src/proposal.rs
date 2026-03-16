// Proposal types matching go-algorand/agreement/proposal.go.
//
// - `UnauthenticatedProposal`: a Block + VRF seed proof + original period/proposer.
// - `verify_proposer`: verify the proposer's VRF seed proof against the expected seed.
//
// `ProposalValue` is defined in vote.rs and re-exported from lib.rs.

use algo_codec::{canonical_encode_unauthenticated_proposal, compute_block_digest};
use algo_consensus_crypto::vrf::VrfPubkey;
use algo_types::{Address, Block, Digest};

use crate::hashable::{hash_obj, hash_rep, Hashable};
use crate::seed::{Seed, VrfOutput};
use crate::step::Period;
use crate::vote::ProposalValue;
use crate::VRF_PROOF_SIZE;

// ---------------------------------------------------------------------------
// UnauthenticatedProposal
// ---------------------------------------------------------------------------

/// An unauthenticated proposal — a Block plus everything needed to validate it.
///
/// Mirrors Go's `agreement.unauthenticatedProposal`:
/// ```go
/// type unauthenticatedProposal struct {
///     bookkeeping.Block
///     SeedProof crypto.VrfProof `codec:"sdpf"`
///     OriginalPeriod   period         `codec:"oper"`
///     OriginalProposer basics.Address `codec:"oprop"`
/// }
/// ```
///
/// The `Hashable` implementation uses HashID `"PL"` (protocol.Payload).
#[derive(Debug, Clone)]
pub struct UnauthenticatedProposal {
    /// The block being proposed.
    pub block: Block,
    /// VRF proof for the seed derivation (80 bytes).
    pub seed_proof: [u8; VRF_PROOF_SIZE],
    /// The period in which the proposal was originally made.
    pub original_period: Period,
    /// The address of the original proposer.
    pub original_proposer: Address,
}

impl UnauthenticatedProposal {
    /// Compute the `ProposalValue` for this proposal.
    ///
    /// Mirrors Go's `unauthenticatedProposal.value()`:
    /// ```go
    /// func (p unauthenticatedProposal) value() proposalValue {
    ///     return proposalValue{
    ///         OriginalPeriod:   p.OriginalPeriod,
    ///         OriginalProposer: p.OriginalProposer,
    ///         BlockDigest:      p.Digest(),
    ///         EncodingDigest:   crypto.HashObj(p),
    ///     }
    /// }
    /// ```
    pub fn value(&self) -> ProposalValue {
        ProposalValue {
            original_period: self.original_period,
            original_proposer: self.original_proposer,
            block_digest: compute_block_digest(&self.block),
            encoding_digest: hash_obj(self),
        }
    }

    /// Returns the round of the proposed block.
    pub fn round(&self) -> algo_types::Round {
        self.block.round
    }

    /// Returns the seed from the proposed block header.
    pub fn seed(&self) -> Seed {
        Seed(self.block.seed)
    }

    /// Returns the proposer from the proposed block header.
    pub fn proposer(&self) -> Address {
        self.block.proposer
    }

    /// Returns the proposer payout from the proposed block header.
    pub fn proposer_payout(&self) -> u64 {
        self.block.proposer_payout
    }
}

impl Hashable for UnauthenticatedProposal {
    /// HashID = `"PL"` (protocol.Payload).
    fn hash_id() -> &'static [u8] {
        b"PL"
    }

    /// Canonical msgpack encoding of the unauthenticated proposal.
    ///
    /// This produces a flattened msgpack map matching Go's encoding:
    /// all BlockHeader fields + payset ("txns") + "sdpf" + "oper" + "oprop".
    fn to_be_hashed(&self) -> Vec<u8> {
        canonical_encode_unauthenticated_proposal(
            &self.block,
            &self.seed_proof,
            self.original_period.0,
            &self.original_proposer,
        )
    }
}

// ---------------------------------------------------------------------------
// verify_proposer
// ---------------------------------------------------------------------------

/// Errors from proposal verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalError {
    /// The proposer in the block header doesn't match the original proposer.
    WrongProposer {
        header_proposer: Address,
        original_proposer: Address,
    },
    /// The VRF seed proof is invalid.
    InvalidSeedProof,
    /// The derived seed doesn't match the block header's seed.
    SeedMismatch { expected: Seed, actual: Seed },
}

impl std::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongProposer {
                header_proposer,
                original_proposer,
            } => write!(
                f,
                "wrong proposer ({:?} != {:?})",
                header_proposer, original_proposer
            ),
            Self::InvalidSeedProof => write!(f, "seed proof malformed"),
            Self::SeedMismatch { expected, actual } => {
                write!(f, "seed mismatch ({:?} != {:?})", expected, actual)
            }
        }
    }
}

impl std::error::Error for ProposalError {}

/// Verify the proposer fields of an unauthenticated proposal.
///
/// This implements a subset of Go's `verifyProposer()` logic, checking:
///
/// 1. If the block header has a non-zero Proposer, it must match
///    the proposal's OriginalProposer.
///
/// 2. The VRF seed proof must be valid:
///    - For period 0: verify the VRF proof against the selection key
///      and the previous seed, then derive the new seed.
///    - For period > 0: the seed is derived from hashing the previous seed
///      (no VRF verification needed for the seed proof itself).
///
/// 3. The derived seed must match the seed in the block header.
///
/// Parameters:
/// - `proposal`: the unauthenticated proposal to verify
/// - `prev_seed`: the seed from the previous round (from `seedRound`)
/// - `selection_id`: the proposer's VRF selection public key (32 bytes)
/// - `history`: optional history digest for seed rerandomization
///
/// Note: This is a simplified version focused on seed verification.
/// Full verification (payout eligibility, etc.) requires ledger access
/// and will be added when the agreement service is implemented.
pub fn verify_proposer(
    proposal: &UnauthenticatedProposal,
    prev_seed: &Seed,
    selection_id: &[u8; 32],
    history: Option<Digest>,
) -> Result<(), ProposalError> {
    let value = proposal.value();

    // Check 1: proposer consistency
    let header_proposer = proposal.proposer();
    if !header_proposer.is_zero() && header_proposer != value.original_proposer {
        return Err(ProposalError::WrongProposer {
            header_proposer,
            original_proposer: value.original_proposer,
        });
    }

    // Check 2 & 3: seed derivation and verification
    let expected_seed = if value.original_period.0 == 0 {
        // Period 0: verify VRF proof against selection key
        // Go passes HashRep(prevSeed) = "SD" || seed_bytes to VRF verify
        let verifier = VrfPubkey::from_bytes(*selection_id);
        let vrf_proof = algo_consensus_crypto::vrf::VrfProof(proposal.seed_proof);
        let vrf_message = hash_rep(prev_seed);

        let vrf_out = verifier
            .verify(&vrf_proof, &vrf_message)
            .ok_or(ProposalError::InvalidSeedProof)?;

        // Derive alpha = HashObj(ProposerSeed{addr, vrf_output})
        let vrf_output: VrfOutput = vrf_out.0;
        crate::seed::derive_seed_period_zero(&value.original_proposer, &vrf_output, history)
    } else {
        // Period > 0: seed derived from hashing previous seed
        crate::seed::derive_seed_period_nonzero(prev_seed, history)
    };

    // Check that the derived seed matches the block header
    let actual_seed = proposal.seed();
    if actual_seed != expected_seed {
        return Err(ProposalError::SeedMismatch {
            expected: expected_seed,
            actual: actual_seed,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::vrf::VrfKeypair;
    use algo_types::Round;

    // ── UnauthenticatedProposal tests ────────────────────────────

    fn make_test_block() -> Block {
        Block {
            round: Round(100),
            seed: [0x42; 32],
            current_protocol: "future".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn unauthenticated_proposal_hash_id_is_pl() {
        assert_eq!(UnauthenticatedProposal::hash_id(), b"PL");
    }

    #[test]
    fn unauthenticated_proposal_hashing_deterministic() {
        let prop = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0xaa; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };
        let d1 = hash_obj(&prop);
        let d2 = hash_obj(&prop);
        assert_eq!(d1, d2);
    }

    #[test]
    fn unauthenticated_proposal_different_period_different_hash() {
        let prop1 = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0xaa; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };
        let prop2 = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0xaa; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };
        assert_ne!(hash_obj(&prop1), hash_obj(&prop2));
    }

    #[test]
    fn unauthenticated_proposal_value_computation() {
        let prop = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0xaa; VRF_PROOF_SIZE],
            original_period: Period(3),
            original_proposer: Address([0x22; 32]),
        };

        let value = prop.value();

        // Check that value fields match
        assert_eq!(value.original_period, Period(3));
        assert_eq!(value.original_proposer, Address([0x22; 32]));

        // Block digest should match compute_block_digest
        assert_eq!(value.block_digest, compute_block_digest(&prop.block));

        // Encoding digest should match hash_obj of the proposal
        assert_eq!(value.encoding_digest, hash_obj(&prop));
    }

    #[test]
    fn unauthenticated_proposal_value_is_deterministic() {
        let prop = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0xaa; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x33; 32]),
        };
        let v1 = prop.value();
        let v2 = prop.value();
        assert_eq!(v1, v2);
    }

    #[test]
    fn unauthenticated_proposal_round() {
        let prop = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0; 32]),
        };
        assert_eq!(prop.round(), Round(100));
    }

    #[test]
    fn unauthenticated_proposal_seed() {
        let prop = UnauthenticatedProposal {
            block: make_test_block(),
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0; 32]),
        };
        assert_eq!(prop.seed(), Seed([0x42; 32]));
    }

    #[test]
    fn unauthenticated_proposal_encoding_includes_seed_proof() {
        // Verify that the encoding actually includes the seed proof field
        let prop = UnauthenticatedProposal {
            block: Block::default(),
            seed_proof: [0xbb; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0; 32]),
        };
        let encoded = prop.to_be_hashed();
        // The encoded bytes should contain "sdpf" as a field key
        let has_sdpf = encoded
            .windows(4)
            .any(|w| w == [b's', b'd', b'p', b'f']);
        assert!(has_sdpf, "encoding must contain 'sdpf' field");
    }

    #[test]
    fn unauthenticated_proposal_encoding_includes_oper() {
        let prop = UnauthenticatedProposal {
            block: Block::default(),
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(5),
            original_proposer: Address([0; 32]),
        };
        let encoded = prop.to_be_hashed();
        let has_oper = encoded
            .windows(4)
            .any(|w| w == [b'o', b'p', b'e', b'r']);
        assert!(has_oper, "encoding must contain 'oper' field");
    }

    #[test]
    fn unauthenticated_proposal_encoding_includes_oprop() {
        let prop = UnauthenticatedProposal {
            block: Block::default(),
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };
        let encoded = prop.to_be_hashed();
        let has_oprop = encoded
            .windows(5)
            .any(|w| w == [b'o', b'p', b'r', b'o', b'p']);
        assert!(has_oprop, "encoding must contain 'oprop' field");
    }

    // ── verify_proposer tests ────────────────────────────────────

    #[test]
    fn verify_proposer_wrong_header_proposer() {
        let mut block = make_test_block();
        block.proposer = Address([0x99; 32]); // Non-zero, different from original

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(&prop, &Seed([0; 32]), &[0; 32], None);

        assert!(matches!(result, Err(ProposalError::WrongProposer { .. })));
    }

    #[test]
    fn verify_proposer_zero_header_proposer_ok() {
        // A zero proposer in the header should not cause a WrongProposer error
        // (it will fail on seed verification instead)
        let mut block = make_test_block();
        block.proposer = Address([0; 32]); // Zero proposer

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(&prop, &Seed([0; 32]), &[0; 32], None);

        // Should fail on seed verification, not proposer check
        assert!(!matches!(result, Err(ProposalError::WrongProposer { .. })));
    }

    #[test]
    fn verify_proposer_invalid_seed_proof_period_zero() {
        let block = make_test_block();
        let kp = VrfKeypair::from_seed([7u8; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0xff; VRF_PROOF_SIZE], // Invalid proof
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(&prop, &Seed([0xab; 32]), kp.pk.as_bytes(), None);

        assert_eq!(result, Err(ProposalError::InvalidSeedProof));
    }

    #[test]
    fn verify_proposer_valid_seed_period_zero() {
        // Create a valid VRF proof and compute the expected seed
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        // Generate a valid VRF proof for the previous seed using hash_rep
        // Go passes HashRep(prevSeed) = "SD" || seed_bytes to VRF
        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed =
            crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        // Create a block with the expected seed
        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]); // Zero proposer (not checked strictly)

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let result = verify_proposer(&prop, &prev_seed, kp.pk.as_bytes(), None);

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn verify_proposer_valid_seed_period_nonzero() {
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE], // Not checked for period > 0
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(
            &prop,
            &prev_seed,
            &[0; 32], // Selection ID not used for period > 0
            None,
        );

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn verify_proposer_seed_mismatch() {
        let prev_seed = Seed([0xab; 32]);

        let mut block = make_test_block();
        block.seed = [0xff; 32]; // Wrong seed
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(&prop, &prev_seed, &[0; 32], None);

        assert!(matches!(result, Err(ProposalError::SeedMismatch { .. })));
    }

    #[test]
    fn verify_proposer_with_history_period_nonzero() {
        let prev_seed = Seed([0xab; 32]);
        let history = Digest([0xcc; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, Some(history));

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(2),
            original_proposer: Address([0x11; 32]),
        };

        let result = verify_proposer(&prop, &prev_seed, &[0; 32], Some(history));

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn verify_proposer_with_history_period_zero() {
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);
        let history = Digest([0xdd; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed =
            crate::seed::derive_seed_period_zero(&proposer, &vrf_output, Some(history));

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let result = verify_proposer(&prop, &prev_seed, kp.pk.as_bytes(), Some(history));

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn verify_proposer_matching_header_proposer_ok() {
        // When header proposer matches original proposer, it should pass that check
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed =
            crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = proposer; // Matches original proposer

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let result = verify_proposer(&prop, &prev_seed, kp.pk.as_bytes(), None);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    // ── ProposalError display tests ──────────────────────────────

    #[test]
    fn proposal_error_display() {
        let err = ProposalError::InvalidSeedProof;
        assert_eq!(format!("{err}"), "seed proof malformed");

        let err = ProposalError::SeedMismatch {
            expected: Seed([0; 32]),
            actual: Seed([1; 32]),
        };
        let msg = format!("{err}");
        assert!(msg.contains("seed mismatch"));

        let err = ProposalError::WrongProposer {
            header_proposer: Address([0x01; 32]),
            original_proposer: Address([0x02; 32]),
        };
        let msg = format!("{err}");
        assert!(msg.contains("wrong proposer"));
    }
}
