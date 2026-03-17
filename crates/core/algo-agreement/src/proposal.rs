// Proposal types matching go-algorand/agreement/proposal.go.
//
// - `UnauthenticatedProposal`: a Block + VRF seed proof + original period/proposer.
// - `verify_proposer`: verify the proposer's VRF seed proof against the expected seed,
//   payout eligibility, and selection ID — all sourced from the ledger.
// - `payout_eligible`: check whether a proposer is eligible for block incentive payouts.
//
// `ProposalValue` is defined in vote.rs and re-exported from lib.rs.

use algo_codec::{canonical_encode_unauthenticated_proposal, compute_block_digest};
use algo_consensus_crypto::vrf::VrfPubkey;
use algo_types::{Address, Block, Round};

use crate::hashable::{hash_obj, hash_rep, Hashable};
use crate::ledger_reader::{LedgerError, LedgerReader, OnlineAccountData};
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

impl Default for UnauthenticatedProposal {
    fn default() -> Self {
        Self {
            block: Block::default(),
            seed_proof: [0u8; VRF_PROOF_SIZE],
            original_period: Period(0),
            original_proposer: Address([0u8; 32]),
        }
    }
}

impl UnauthenticatedProposal {
    /// Returns the block digest of the proposal.
    pub fn block_digest(&self) -> algo_types::Digest {
        compute_block_digest(&self.block)
    }

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
// verify_proposer + payout_eligible
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
    /// A ledger lookup failed during verification.
    LedgerError(String),
    /// Proposer is ineligible for payouts but block has a non-zero ProposerPayout.
    IneligibleProposerPayout { proposer: Address, payout: u64 },
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
            Self::LedgerError(msg) => write!(f, "ledger error: {msg}"),
            Self::IneligibleProposerPayout { proposer, payout } => {
                write!(
                    f,
                    "proposer payout ({payout}) for ineligible Proposer {proposer:?}"
                )
            }
        }
    }
}

impl std::error::Error for ProposalError {}

impl From<LedgerError> for ProposalError {
    fn from(e: LedgerError) -> Self {
        Self::LedgerError(e.to_string())
    }
}

/// Determine whether the proposer is eligible for block incentive payouts.
///
/// Mirrors Go's `payoutEligible()` in `agreement/proposal.go`:
/// - Looks up the proposer's balance record at the balance round
/// - Checks `IncentiveEligible` flag
/// - Checks balance is within `[Payouts.MinBalance, Payouts.MaxBalance]`
///
/// Returns `(eligible, proposer_record)`.
pub fn payout_eligible(
    rnd: Round,
    proposer: &Address,
    ledger: &dyn LedgerReader,
    cparams: &algo_types::ConsensusParams,
) -> Result<(bool, OnlineAccountData), ProposalError> {
    let bal_round = crate::lookback::balance_round(rnd, cparams);
    let balance_record = ledger.lookup_agreement(bal_round, proposer)?;

    // Get the consensus params for the balance round to check min/max balance.
    // When payouts begin, nobody could possibly have IncentiveEligible set in
    // the balanceRound, so the min/max check is irrelevant at that point.
    let balance_params = ledger.consensus_params(bal_round)?;

    let eligible = balance_record.incentive_eligible
        && balance_record.micro_algos >= balance_params.payouts_min_balance
        && balance_record.micro_algos <= balance_params.payouts_max_balance;

    Ok((eligible, balance_record))
}

/// Verify the proposer fields of an unauthenticated proposal.
///
/// Mirrors Go's `verifyProposer()` in `agreement/proposal.go`, checking:
///
/// 1. If the block header has a non-zero Proposer, it must match
///    the proposal's OriginalProposer.
///
/// 2. Payout eligibility: looks up the proposer's account from the ledger
///    and checks incentive eligibility. If ineligible, ProposerPayout must be 0.
///
/// 3. The VRF seed proof must be valid:
///    - For period 0: verify the VRF proof against the selection key
///      (sourced from the ledger balance record) and the previous seed,
///      then derive the new seed.
///    - For period > 0: the seed is derived from hashing the previous seed.
///
/// 4. The derived seed must match the seed in the block header.
pub fn verify_proposer(
    proposal: &UnauthenticatedProposal,
    ledger: &dyn LedgerReader,
) -> Result<(), ProposalError> {
    let value = proposal.value();
    let rnd = proposal.round();

    // Check 1: proposer consistency
    // The Proposer is *either* correct or missing. `eval` package will use
    // Payouts.Enabled to confirm which it should be.
    let header_proposer = proposal.proposer();
    if !header_proposer.is_zero() && header_proposer != value.original_proposer {
        return Err(ProposalError::WrongProposer {
            header_proposer,
            original_proposer: value.original_proposer,
        });
    }

    // Get consensus params for the proposal round
    let cparams = ledger.consensus_params(crate::lookback::params_round(rnd))?;

    // Check 2: payout eligibility
    // We pass OriginalProposer (not p.Proposer) so the call returns the proper
    // record even before Payouts.Enabled.
    let (eligible, proposer_record) =
        payout_eligible(rnd, &value.original_proposer, ledger, &cparams)?;
    if !eligible && proposal.proposer_payout() > 0 {
        return Err(ProposalError::IneligibleProposerPayout {
            proposer: proposal.proposer(),
            payout: proposal.proposer_payout(),
        });
    }

    // Check 3 & 4: seed derivation and verification
    let seed_rnd = crate::lookback::seed_round(rnd, &cparams);
    let prev_seed = ledger.seed(seed_rnd).map_err(|e| {
        ProposalError::LedgerError(format!("failed to read seed of round {}: {e}", seed_rnd.0))
    })?;

    // Compute history digest for seed rerandomization
    let history = {
        let rerand = rnd.0 % (cparams.seed_lookback * cparams.seed_refresh_interval);
        if rerand < cparams.seed_lookback {
            let digrnd = rnd.sub_saturate(cparams.seed_lookback * cparams.seed_refresh_interval);
            let old_digest = ledger.lookup_digest(digrnd).map_err(|e| {
                ProposalError::LedgerError(format!(
                    "could not lookup old entry digest (for seed) from round {}: {e}",
                    digrnd.0
                ))
            })?;
            Some(old_digest)
        } else {
            None
        }
    };

    let expected_seed = if value.original_period.0 == 0 {
        // Period 0: verify VRF proof against selection key from ledger
        let selection_id = proposer_record.selection_id;
        let verifier = VrfPubkey::from_bytes(selection_id);
        let vrf_proof = algo_consensus_crypto::vrf::VrfProof(proposal.seed_proof);
        let vrf_message = hash_rep(&prev_seed);

        let vrf_out = verifier
            .verify(&vrf_proof, &vrf_message)
            .ok_or(ProposalError::InvalidSeedProof)?;

        // Derive alpha = HashObj(ProposerSeed{addr, vrf_output})
        let vrf_output: VrfOutput = vrf_out.0;
        crate::seed::derive_seed_period_zero(&value.original_proposer, &vrf_output, history)
    } else {
        // Period > 0: seed derived from hashing previous seed
        crate::seed::derive_seed_period_nonzero(&prev_seed, history)
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
    use algo_types::{ConsensusParams, Digest};
    use std::collections::HashMap;

    // ── Mock LedgerReader ─────────────────────────────────────────

    struct MockLedgerReader {
        /// Default consensus params (used when no per-round override exists).
        params: ConsensusParams,
        /// Per-round consensus params overrides.
        params_by_round: HashMap<Round, ConsensusParams>,
        seed: Seed,
        accounts: HashMap<Address, OnlineAccountData>,
        /// Per-round digest overrides.
        digests_by_round: HashMap<Round, Digest>,
        /// Track which rounds were queried for consensus_params.
        queried_params_rounds: std::cell::RefCell<Vec<Round>>,
    }

    impl MockLedgerReader {
        fn new(params: ConsensusParams) -> Self {
            Self {
                params,
                params_by_round: HashMap::new(),
                seed: Seed([0xab; 32]),
                accounts: HashMap::new(),
                digests_by_round: HashMap::new(),
                queried_params_rounds: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn with_seed(mut self, seed: Seed) -> Self {
            self.seed = seed;
            self
        }

        fn add_account(&mut self, addr: Address, data: OnlineAccountData) {
            self.accounts.insert(addr, data);
        }

        fn set_params_for_round(&mut self, round: Round, params: ConsensusParams) {
            self.params_by_round.insert(round, params);
        }

        fn set_digest_for_round(&mut self, round: Round, digest: Digest) {
            self.digests_by_round.insert(round, digest);
        }

        fn queried_params_rounds(&self) -> Vec<Round> {
            self.queried_params_rounds.borrow().clone()
        }
    }

    impl LedgerReader for MockLedgerReader {
        fn seed(&self, _round: Round) -> Result<Seed, LedgerError> {
            Ok(self.seed)
        }

        fn lookup_agreement(
            &self,
            _round: Round,
            addr: &Address,
        ) -> Result<OnlineAccountData, LedgerError> {
            self.accounts
                .get(addr)
                .cloned()
                .ok_or(LedgerError::Other(format!("account not found: {addr:?}")))
        }

        fn circulation(&self, _rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
            Ok(10_000_000)
        }

        fn lookup_digest(&self, round: Round) -> Result<Digest, LedgerError> {
            Ok(self
                .digests_by_round
                .get(&round)
                .cloned()
                .unwrap_or(Digest([0u8; 32])))
        }

        fn consensus_params(&self, round: Round) -> Result<ConsensusParams, LedgerError> {
            self.queried_params_rounds.borrow_mut().push(round);
            if let Some(p) = self.params_by_round.get(&round) {
                Ok(p.clone())
            } else {
                Ok(self.params.clone())
            }
        }

        fn next_round(&self) -> Round {
            Round(1)
        }

        fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
            Ok(algo_types::CONSENSUS_V41.to_string())
        }

        fn wait_for_round(&self, _round: Round) -> Result<(), LedgerError> {
            Ok(())
        }
    }

    fn default_online_account(selection_id: [u8; 32]) -> OnlineAccountData {
        OnlineAccountData {
            micro_algos: 50_000_000_000, // 50k Algos, within payout range
            vote_id: [0u8; 32],
            selection_id,
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 0,
            incentive_eligible: false,
            last_proposed: Round(0),
            last_heartbeat: Round(0),
            state_proof_id: [0u8; 64],
        }
    }

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

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
        let has_sdpf = encoded.windows(4).any(|w| w == [b's', b'd', b'p', b'f']);
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
        let has_oper = encoded.windows(4).any(|w| w == [b'o', b'p', b'e', b'r']);
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

    /// Helper: create a mock ledger with the given proposer account and seed,
    /// and return the (ledger, proposer_address).
    fn make_ledger_with_proposer(
        selection_id: [u8; 32],
        prev_seed: Seed,
        incentive_eligible: bool,
        micro_algos: u64,
    ) -> (MockLedgerReader, Address) {
        let proposer = Address([0x11; 32]);
        let mut account = default_online_account(selection_id);
        account.incentive_eligible = incentive_eligible;
        account.micro_algos = micro_algos;
        let mut ledger = MockLedgerReader::new(v41_params()).with_seed(prev_seed);
        ledger.add_account(proposer, account);
        (ledger, proposer)
    }

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

        let (ledger, _) = make_ledger_with_proposer([0; 32], Seed([0; 32]), false, 0);
        let result = verify_proposer(&prop, &ledger);

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

        let (ledger, _) = make_ledger_with_proposer([0; 32], Seed([0; 32]), false, 0);
        let result = verify_proposer(&prop, &ledger);

        // Should fail on seed verification, not proposer check
        assert!(!matches!(result, Err(ProposalError::WrongProposer { .. })));
    }

    #[test]
    fn verify_proposer_invalid_seed_proof_period_zero() {
        let kp = VrfKeypair::from_seed([7u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let block = make_test_block();
        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0xff; VRF_PROOF_SIZE], // Invalid proof
            original_period: Period(0),
            original_proposer: Address([0x11; 32]),
        };

        let (ledger, _) = make_ledger_with_proposer(*kp.pk.as_bytes(), prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

        assert_eq!(result, Err(ProposalError::InvalidSeedProof));
    }

    #[test]
    fn verify_proposer_valid_seed_period_zero() {
        // Create a valid VRF proof and compute the expected seed
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed = crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]); // Zero proposer (not checked strictly)

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let (ledger, _) = make_ledger_with_proposer(*kp.pk.as_bytes(), prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

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
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

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

        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

        assert!(matches!(result, Err(ProposalError::SeedMismatch { .. })));
    }

    #[test]
    fn verify_proposer_with_history_period_nonzero() {
        let prev_seed = Seed([0xab; 32]);
        // history is computed internally from ledger.lookup_digest when the
        // round mod falls in the rerandomization window — our mock always
        // returns Digest([0; 32]), so we compute the expected seed using that.
        // With round 100, seed_lookback=2, seed_refresh_interval=80:
        // rerand = 100 % (2*80) = 100, which is >= 2, so no history is mixed in.
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(2),
            original_proposer: Address([0x11; 32]),
        };

        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn verify_proposer_with_history_period_zero() {
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        // Round 100: rerand = 100 % 160 = 100, >= 2 => no history
        let expected_seed = crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let (ledger, _) = make_ledger_with_proposer(*kp.pk.as_bytes(), prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);

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
        let expected_seed = crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = proposer; // Matches original proposer

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let (ledger, _) = make_ledger_with_proposer(*kp.pk.as_bytes(), prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    // ── Payout eligibility tests ─────────────────────────────────

    #[test]
    fn payout_eligible_proposer_with_nonzero_payout_passes() {
        // An eligible proposer with non-zero payout should pass verification
        let kp = VrfKeypair::from_seed([42u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed = crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = proposer;
        block.proposer_payout = 1000; // Non-zero payout

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        // Eligible: incentive_eligible=true, balance within range
        let (ledger, _) = make_ledger_with_proposer(
            *kp.pk.as_bytes(),
            prev_seed,
            true,           // incentive eligible
            50_000_000_000, // 50k Algos, within v41 payout range
        );
        let result = verify_proposer(&prop, &ledger);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn payout_ineligible_proposer_with_nonzero_payout_fails() {
        // An ineligible proposer with non-zero payout should fail
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);
        block.proposer_payout = 500; // Non-zero payout but ineligible

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        // Not eligible: incentive_eligible=false
        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 50_000_000_000);
        let result = verify_proposer(&prop, &ledger);

        assert!(
            matches!(result, Err(ProposalError::IneligibleProposerPayout { .. })),
            "expected IneligibleProposerPayout, got {:?}",
            result
        );
    }

    #[test]
    fn payout_ineligible_proposer_with_zero_payout_passes() {
        // An ineligible proposer with zero payout should pass (seed check still applies)
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);
        block.proposer_payout = 0; // Zero payout, ineligible is fine

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 50_000_000_000);
        let result = verify_proposer(&prop, &ledger);

        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn payout_eligible_balance_too_low() {
        // Account is incentive_eligible but balance is below MinBalance
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);
        block.proposer_payout = 100; // Non-zero

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        // incentive_eligible=true but balance below MinBalance (30_000_000_000)
        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, true, 1_000_000);
        let result = verify_proposer(&prop, &ledger);

        assert!(
            matches!(result, Err(ProposalError::IneligibleProposerPayout { .. })),
            "expected IneligibleProposerPayout for low balance, got {:?}",
            result
        );
    }

    #[test]
    fn payout_eligible_balance_too_high() {
        // Account is incentive_eligible but balance exceeds MaxBalance
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);
        block.proposer_payout = 100; // Non-zero

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        // incentive_eligible=true but balance above MaxBalance (70_000_000_000_000)
        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, true, 100_000_000_000_000);
        let result = verify_proposer(&prop, &ledger);

        assert!(
            matches!(result, Err(ProposalError::IneligibleProposerPayout { .. })),
            "expected IneligibleProposerPayout for high balance, got {:?}",
            result
        );
    }

    #[test]
    fn selection_id_sourced_from_ledger() {
        // Verify that the selection ID is sourced from the ledger, not passed as a parameter.
        // Use a VRF keypair, register the account with that selection key, and verify.
        let kp = VrfKeypair::from_seed([99u8; 32]);
        let prev_seed = Seed([0xab; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let expected_seed = crate::seed::derive_seed_period_zero(&proposer, &vrf_output, None);

        let mut block = make_test_block();
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        // Register with the correct selection key from the ledger
        let (ledger, _) = make_ledger_with_proposer(*kp.pk.as_bytes(), prev_seed, false, 0);
        let result = verify_proposer(&prop, &ledger);
        assert!(
            result.is_ok(),
            "expected Ok with correct selection key from ledger, got {:?}",
            result
        );

        // Now register with a WRONG selection key — should fail
        let wrong_kp = VrfKeypair::from_seed([0u8; 32]);
        let (wrong_ledger, _) =
            make_ledger_with_proposer(*wrong_kp.pk.as_bytes(), prev_seed, false, 0);
        let result2 = verify_proposer(&prop, &wrong_ledger);
        assert_eq!(
            result2,
            Err(ProposalError::InvalidSeedProof),
            "expected InvalidSeedProof with wrong selection key"
        );
    }

    // ── payout_eligible unit tests ───────────────────────────────

    #[test]
    fn payout_eligible_all_conditions_met() {
        let params = v41_params();
        let proposer = Address([0x11; 32]);
        let mut ledger = MockLedgerReader::new(params.clone());
        let mut account = default_online_account([0; 32]);
        account.incentive_eligible = true;
        account.micro_algos = 50_000_000_000; // within range
        ledger.add_account(proposer, account);

        let (eligible, _record) =
            payout_eligible(Round(1000), &proposer, &ledger, &params).unwrap();
        assert!(eligible);
    }

    #[test]
    fn payout_eligible_not_incentive_eligible() {
        let params = v41_params();
        let proposer = Address([0x11; 32]);
        let mut ledger = MockLedgerReader::new(params.clone());
        let mut account = default_online_account([0; 32]);
        account.incentive_eligible = false;
        account.micro_algos = 50_000_000_000;
        ledger.add_account(proposer, account);

        let (eligible, _) = payout_eligible(Round(1000), &proposer, &ledger, &params).unwrap();
        assert!(!eligible);
    }

    #[test]
    fn payout_eligible_below_min_balance() {
        let params = v41_params();
        let proposer = Address([0x11; 32]);
        let mut ledger = MockLedgerReader::new(params.clone());
        let mut account = default_online_account([0; 32]);
        account.incentive_eligible = true;
        account.micro_algos = 100; // way below min
        ledger.add_account(proposer, account);

        let (eligible, _) = payout_eligible(Round(1000), &proposer, &ledger, &params).unwrap();
        assert!(!eligible);
    }

    #[test]
    fn payout_eligible_above_max_balance() {
        let params = v41_params();
        let proposer = Address([0x11; 32]);
        let mut ledger = MockLedgerReader::new(params.clone());
        let mut account = default_online_account([0; 32]);
        account.incentive_eligible = true;
        account.micro_algos = 100_000_000_000_000; // above max
        ledger.add_account(proposer, account);

        let (eligible, _) = payout_eligible(Round(1000), &proposer, &ledger, &params).unwrap();
        assert!(!eligible);
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

        let err = ProposalError::LedgerError("test".to_string());
        assert_eq!(format!("{err}"), "ledger error: test");

        let err = ProposalError::IneligibleProposerPayout {
            proposer: Address([0x01; 32]),
            payout: 500,
        };
        let msg = format!("{err}");
        assert!(msg.contains("proposer payout"));
        assert!(msg.contains("500"));
        assert!(msg.contains("ineligible"));
    }

    // ── Mock round-differentiation tests ─────────────────────────

    #[test]
    fn consensus_params_queries_correct_rounds() {
        // verify_proposer calls consensus_params with params_round (rnd - 2)
        // and payout_eligible calls it with balance_round. We verify those
        // rounds are actually passed to the mock.
        let prev_seed = Seed([0xab; 32]);
        let expected_seed = crate::seed::derive_seed_period_nonzero(&prev_seed, None);

        let mut block = make_test_block(); // round 100
        block.seed = expected_seed.0;
        block.proposer = Address([0; 32]);
        block.proposer_payout = 0;

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let (ledger, _) = make_ledger_with_proposer([0; 32], prev_seed, false, 50_000_000_000);
        let result = verify_proposer(&prop, &ledger);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let queried = ledger.queried_params_rounds();
        // verify_proposer queries params_round(100) = 98
        assert!(
            queried.contains(&Round(98)),
            "expected params_round(100) = Round(98) to be queried, got {:?}",
            queried
        );
        // payout_eligible queries balance_round, which is Round(0) since 100 < 320
        assert!(
            queried.contains(&Round(0)),
            "expected balance_round to be queried (Round(0)), got {:?}",
            queried
        );
    }

    #[test]
    fn consensus_params_per_round_override() {
        // Verify the mock can return different params per round
        let params = v41_params();
        let mut ledger = MockLedgerReader::new(params.clone());

        // Set a different payouts_min_balance for round 0
        let mut alt_params = params.clone();
        alt_params.payouts_min_balance = 999_999;
        ledger.set_params_for_round(Round(0), alt_params.clone());

        // Query round 0 should return the override
        let p0 = ledger.consensus_params(Round(0)).unwrap();
        assert_eq!(p0.payouts_min_balance, 999_999);

        // Query round 1 should return the default
        let p1 = ledger.consensus_params(Round(1)).unwrap();
        assert_eq!(p1.payouts_min_balance, params.payouts_min_balance);
    }

    // ── Seed history rerandomization test ─────────────────────────

    #[test]
    fn verify_proposer_with_seed_rerandomization_period_nonzero() {
        // Round 320: rerand = 320 % (2 * 80) = 320 % 160 = 0, which is < 2
        // so history mixing applies.
        // digrnd = 320 - 160 = 160
        let params = v41_params();
        let prev_seed = Seed([0xab; 32]);

        // The history digest for round 160
        let history_digest = Digest([0xcc; 32]);

        // Compute expected seed WITH history mixing
        let expected_seed =
            crate::seed::derive_seed_period_nonzero(&prev_seed, Some(history_digest));

        let mut block = Block {
            round: Round(320),
            seed: expected_seed.0,
            current_protocol: "future".to_string(),
            ..Default::default()
        };
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: [0; VRF_PROOF_SIZE],
            original_period: Period(1),
            original_proposer: Address([0x11; 32]),
        };

        let mut ledger = MockLedgerReader::new(params).with_seed(prev_seed);
        // Set the digest for round 160 (the history round)
        ledger.set_digest_for_round(Round(160), history_digest);
        let mut account = default_online_account([0; 32]);
        account.micro_algos = 50_000_000_000;
        ledger.add_account(Address([0x11; 32]), account);

        let result = verify_proposer(&prop, &ledger);
        assert!(
            result.is_ok(),
            "expected Ok for rerandomization path, got {:?}",
            result
        );
    }

    #[test]
    fn verify_proposer_with_seed_rerandomization_period_zero() {
        // Round 320 with period 0: uses VRF proof + history mixing
        let params = v41_params();
        let prev_seed = Seed([0xab; 32]);
        let kp = VrfKeypair::from_seed([42u8; 32]);

        let vrf_message = hash_rep(&prev_seed);
        let (proof, _) = kp.sk.prove(&vrf_message);
        let vrf_out = kp.pk.verify(&proof, &vrf_message).unwrap();
        let vrf_output: VrfOutput = vrf_out.0;

        let proposer = Address([0x11; 32]);
        let history_digest = Digest([0xdd; 32]);

        // Compute expected seed WITH history for period 0
        let expected_seed =
            crate::seed::derive_seed_period_zero(&proposer, &vrf_output, Some(history_digest));

        let mut block = Block {
            round: Round(320),
            seed: expected_seed.0,
            current_protocol: "future".to_string(),
            ..Default::default()
        };
        block.proposer = Address([0; 32]);

        let prop = UnauthenticatedProposal {
            block,
            seed_proof: *proof.as_bytes(),
            original_period: Period(0),
            original_proposer: proposer,
        };

        let mut ledger = MockLedgerReader::new(params).with_seed(prev_seed);
        ledger.set_digest_for_round(Round(160), history_digest);
        let mut account = default_online_account(*kp.pk.as_bytes());
        account.micro_algos = 50_000_000_000;
        ledger.add_account(proposer, account);

        let result = verify_proposer(&prop, &ledger);
        assert!(
            result.is_ok(),
            "expected Ok for period-0 rerandomization path, got {:?}",
            result
        );
    }
}
