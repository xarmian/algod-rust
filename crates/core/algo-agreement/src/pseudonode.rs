// Pseudonode: local proposal and vote generation for the agreement protocol.
//
// Mirrors go-algorand/agreement/pseudonode.go.
//
// The pseudonode creates proposals and votes with a KeyManager which holds
// participation keys. It constructs these messages as if they arrived from an
// external source and were verified. These messages are processed and relayed
// by the state machine just like any other message from an external source.
// This design simplifies the logic required to test and execute proposing and
// voting.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use algo_types::{Address, Round};

use crate::credential::UnauthenticatedCredential;
use crate::events::{EventType, InternalMessage, MessageEvent, Proposal, SerializableError};
use crate::ledger_reader::LedgerReader;
use crate::lookback;
use crate::proposal::UnauthenticatedProposal;
use crate::seed::Seed;
use crate::step::{Period, Step, PROPOSE};
use crate::traits::{
    AgreementKeyManager, BlockFactory, ParticipationAction, ParticipationRecord, UnfinishedBlock,
    AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG,
};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of tasks buffered in the pseudonode verification channel.
///
/// Mirrors Go's `pseudonodeVerificationBacklog`.
pub const PSEUDONODE_VERIFICATION_BACKLOG: usize = 32;

/// Maximum time to wait for pseudonode output to be consumed.
///
/// Mirrors Go's `maxPseudonodeOutputWaitDuration`.
pub const MAX_PSEUDONODE_OUTPUT_WAIT_DURATION: Duration = Duration::from_secs(2);

/// Threshold for logging slow voting-key acquisition.
///
/// Mirrors Go's `votingKeysLoggingDurationThreashold`.
#[allow(dead_code)]
const VOTING_KEYS_LOGGING_DURATION_THRESHOLD: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// PseudonodeError
// ---------------------------------------------------------------------------

/// Errors that can occur during pseudonode operations.
///
/// Mirrors the Go error variables in pseudonode.go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudonodeError {
    /// The pseudonode input channel is full.
    ///
    /// Mirrors Go's `errPseudonodeBacklogFull`.
    BacklogFull {
        round: Round,
        period: Period,
        step: Option<Step>,
    },

    /// No valid participation keys to generate votes for given round.
    ///
    /// Mirrors Go's `errPseudonodeNoVotes`.
    NoVotes,

    /// No valid participation keys to generate proposals for given round.
    ///
    /// Mirrors Go's `errPseudonodeNoProposals`.
    NoProposals,

    /// The crypto verifier closed the output channel prematurely.
    ///
    /// Mirrors Go's `errPseudonodeVerifierClosedChannel`.
    VerifierClosedChannel,

    /// Block assembly failed.
    AssemblyFailed(String),

    /// Proposal creation failed.
    ProposalFailed(String),

    /// Vote creation failed.
    VoteFailed(String),

    /// Ledger lookup failed.
    LedgerError(String),

    /// The pseudonode has been shut down.
    Shutdown,
}

impl fmt::Display for PseudonodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BacklogFull {
                round,
                period,
                step,
            } => {
                if let Some(s) = step {
                    write!(
                        f,
                        "unable to make vote for ({}, {}, {}): pseudonode input channel is full",
                        round, period, s
                    )
                } else {
                    write!(
                        f,
                        "unable to make proposal for ({}, {}): pseudonode input channel is full",
                        round, period
                    )
                }
            }
            Self::NoVotes => write!(
                f,
                "no valid participation keys to generate votes for given round"
            ),
            Self::NoProposals => write!(
                f,
                "no valid participation keys to generate proposals for given round"
            ),
            Self::VerifierClosedChannel => {
                write!(f, "crypto verifier closed the output channel prematurely")
            }
            Self::AssemblyFailed(msg) => write!(f, "block assembly failed: {msg}"),
            Self::ProposalFailed(msg) => write!(f, "proposal creation failed: {msg}"),
            Self::VoteFailed(msg) => write!(f, "vote creation failed: {msg}"),
            Self::LedgerError(msg) => write!(f, "ledger error: {msg}"),
            Self::Shutdown => write!(f, "pseudonode has been shut down"),
        }
    }
}

impl std::error::Error for PseudonodeError {}

// ---------------------------------------------------------------------------
// Pseudonode trait
// ---------------------------------------------------------------------------

/// The pseudonode trait for generating proposals and votes locally.
///
/// Mirrors Go's `pseudonode` interface in agreement/pseudonode.go.
///
/// A pseudonode creates proposals and votes with a KeyManager which holds
/// participation keys. It constructs these messages as if they arrived from
/// an external source and were verified.
pub trait Pseudonode {
    /// Generate block proposals for the given round and period.
    ///
    /// Returns a vector of `MessageEvent`s containing verified proposal votes
    /// and payload-verified events.
    ///
    /// Mirrors Go's `MakeProposals(ctx, round, period) (<-chan externalEvent, error)`.
    fn make_proposals(
        &mut self,
        round: Round,
        period: Period,
    ) -> Result<Vec<MessageEvent>, PseudonodeError>;

    /// Generate votes for a proposal in some round, period, and step.
    ///
    /// Returns a vector of `MessageEvent`s containing verified vote events.
    ///
    /// Mirrors Go's `MakeVotes(ctx, round, period, step, proposalValue, persistStateDone)
    ///     (chan externalEvent, error)`.
    fn make_votes(
        &mut self,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
    ) -> Result<Vec<MessageEvent>, PseudonodeError>;

    /// Direct the pseudonode to exit and clean up resources.
    ///
    /// Mirrors Go's `Quit()`.
    fn quit(&mut self);
}

// ---------------------------------------------------------------------------
// AsyncPseudonode
// ---------------------------------------------------------------------------

/// Full pseudonode implementation for local proposal/vote generation.
///
/// Mirrors Go's `asyncPseudonode` struct in agreement/pseudonode.go.
///
/// Uses participation keys from the KeyManager to determine committee
/// membership, assemble block proposals, and sign votes.
pub struct AsyncPseudonode<F, K, L>
where
    F: BlockFactory,
    K: AgreementKeyManager,
    L: LedgerReader,
{
    /// Block factory for assembling proposals.
    factory: F,
    /// Key manager holding participation keys.
    keys: K,
    /// Ledger reader for balance/seed lookups.
    ledger: L,
    /// Whether the pseudonode has been shut down.
    quit: Arc<AtomicBool>,
    /// Cached participation keys for the current round.
    participation_keys_round: Round,
    /// The cached participation keys.
    participation_keys: Vec<ParticipationRecord>,
}

impl<F, K, L> AsyncPseudonode<F, K, L>
where
    F: BlockFactory,
    K: AgreementKeyManager,
    L: LedgerReader,
{
    /// Creates a new `AsyncPseudonode`.
    ///
    /// Mirrors Go's `makePseudonode(params)`.
    pub fn new(factory: F, keys: K, ledger: L) -> Self {
        Self {
            factory,
            keys,
            ledger,
            quit: Arc::new(AtomicBool::new(false)),
            participation_keys_round: Round(0),
            participation_keys: Vec::new(),
        }
    }

    /// Load the participation keys from the key manager for the given round,
    /// caching them for reuse.
    ///
    /// Mirrors Go's `asyncPseudonode.loadRoundParticipationKeys`.
    fn load_round_participation_keys(&mut self, vote_round: Round) -> &[ParticipationRecord] {
        // If we've already loaded keys for this round, return the cached copy.
        if self.participation_keys_round == vote_round && !self.participation_keys.is_empty() {
            return &self.participation_keys;
        }

        let cparams = match self
            .ledger
            .consensus_params(lookback::params_round(vote_round))
        {
            Ok(p) => p,
            Err(_) => {
                // If we cannot figure out the balance round number, reset the
                // parameters so that we won't be sending any vote.
                self.participation_keys_round = Round(0);
                self.participation_keys = Vec::new();
                return &self.participation_keys;
            }
        };
        let balance_round = lookback::balance_round(vote_round, &cparams);

        self.participation_keys = self.keys.voting_keys(vote_round, balance_round);
        self.participation_keys_round = vote_round;

        &self.participation_keys
    }

    /// Create proposals for the given round and period using all participating
    /// accounts.
    ///
    /// Returns a tuple of (proposals as UnauthenticatedProposal, proposal-votes
    /// as UnauthenticatedVote).
    ///
    /// Mirrors Go's `asyncPseudonode.makeProposals`.
    fn create_proposals(
        &self,
        round: Round,
        period: Period,
        accounts: &[ParticipationRecord],
    ) -> (Vec<ProposalData>, Vec<UnauthenticatedVote>) {
        let addresses: Vec<Address> = accounts.iter().map(|a| a.address).collect();

        let unfinished_block = match self.factory.assemble_block(round, &addresses) {
            Ok(b) => b,
            Err(e) => {
                // If the round is stale, this is normal operation; otherwise log error.
                let _ = e; // In Go, errors other than ErrAssembleBlockRoundStale are logged.
                return (Vec::new(), Vec::new());
            }
        };

        let mut votes = Vec::with_capacity(accounts.len());
        let mut proposals = Vec::with_capacity(accounts.len());

        for acc in accounts {
            // Create the proposal for this block/account.
            match proposal_for_block(
                &acc.address,
                &acc.selection_id,
                unfinished_block.as_ref(),
                period,
                &self.ledger,
            ) {
                Ok((proposal, pv)) => {
                    // Attempt to make the proposal vote.
                    let rv = RawVote {
                        sender: acc.address,
                        round,
                        period,
                        step: PROPOSE,
                        proposal: pv,
                    };

                    match make_vote(&rv, acc, &self.ledger) {
                        Ok(uv) => {
                            proposals.push(proposal);
                            votes.push(uv);
                        }
                        Err(_) => {
                            // In Go, this is logged as a warning and we continue.
                            continue;
                        }
                    }
                }
                Err(_) => {
                    // In Go, this is logged as an error and we continue.
                    continue;
                }
            }
        }

        (proposals, votes)
    }

    /// Create votes for a given proposal value in a given round, period, and step.
    ///
    /// Mirrors Go's `asyncPseudonode.makeVotes`.
    fn create_votes(
        &self,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
        participation: &[ParticipationRecord],
    ) -> Vec<UnauthenticatedVote> {
        let mut votes = Vec::new();

        for part in participation {
            let rv = RawVote {
                sender: part.address,
                round,
                period,
                step,
                proposal,
            };

            match make_vote(&rv, part, &self.ledger) {
                Ok(uv) => votes.push(uv),
                Err(_) => {
                    // In Go, this is logged as a warning and we continue.
                    continue;
                }
            }
        }

        votes
    }
}

impl<F, K, L> Pseudonode for AsyncPseudonode<F, K, L>
where
    F: BlockFactory,
    K: AgreementKeyManager,
    L: LedgerReader,
{
    fn make_proposals(
        &mut self,
        round: Round,
        period: Period,
    ) -> Result<Vec<MessageEvent>, PseudonodeError> {
        if self.quit.load(Ordering::SeqCst) {
            return Err(PseudonodeError::Shutdown);
        }

        // Load participation keys for this round.
        self.load_round_participation_keys(round);
        let participation = self.participation_keys.clone();

        if participation.is_empty() {
            return Err(PseudonodeError::NoProposals);
        }

        // Create proposals and their associated proposal-votes.
        let (proposals, votes) = self.create_proposals(round, period, &participation);

        // Verify the votes (in the Go code this goes through AsyncVoteVerifier;
        // here we verify inline since we don't have the async verifier yet).
        let mut events = Vec::new();

        for (i, uv) in votes.iter().enumerate() {
            // Build the verification parameters from the ledger.
            match verify_vote_from_ledger(uv, &self.ledger) {
                Ok(vote) => {
                    // Emit a voteVerified event for the proposal vote.
                    let msg = InternalMessage {
                        tag: AGREEMENT_VOTE_TAG.to_string(),
                        vote: Some(vote.clone()),
                        unauthenticated_vote: uv.clone(),
                        ..InternalMessage::default()
                    };
                    events.push(MessageEvent {
                        t: EventType::VoteVerified,
                        input: msg,
                        err: None,
                        ..MessageEvent::default()
                    });

                    // Record the participation action.
                    self.keys.record(
                        &vote.raw_vote.sender,
                        vote.raw_vote.round,
                        ParticipationAction::Proposed,
                    );

                    // Emit a payloadVerified event for the corresponding proposal.
                    if i < proposals.len() {
                        let payload_msg = InternalMessage {
                            tag: PROPOSAL_PAYLOAD_TAG.to_string(),
                            unauthenticated_proposal: proposals[i].unauthenticated_proposal.clone(),
                            proposal: Some(Proposal {
                                unauthenticated_proposal: proposals[i]
                                    .unauthenticated_proposal
                                    .clone(),
                                validated_at: Duration::ZERO,
                                received_at: Duration::ZERO,
                            }),
                            ..InternalMessage::default()
                        };
                        events.push(MessageEvent {
                            t: EventType::PayloadVerified,
                            input: payload_msg,
                            err: None,
                            ..MessageEvent::default()
                        });
                    }
                }
                Err(_) => {
                    // This is normal: the account was not selected by sortition.
                    continue;
                }
            }
        }

        Ok(events)
    }

    fn make_votes(
        &mut self,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
    ) -> Result<Vec<MessageEvent>, PseudonodeError> {
        if self.quit.load(Ordering::SeqCst) {
            return Err(PseudonodeError::Shutdown);
        }

        // Load participation keys for this round.
        self.load_round_participation_keys(round);
        let participation = self.participation_keys.clone();

        if participation.is_empty() {
            return Err(PseudonodeError::NoVotes);
        }

        // Create the unauthenticated votes.
        let unverified_votes = self.create_votes(round, period, step, proposal, &participation);

        // Verify the votes and produce events.
        let mut events = Vec::new();

        for uv in &unverified_votes {
            match verify_vote_from_ledger(uv, &self.ledger) {
                Ok(vote) => {
                    let msg = InternalMessage {
                        tag: AGREEMENT_VOTE_TAG.to_string(),
                        vote: Some(vote.clone()),
                        unauthenticated_vote: uv.clone(),
                        ..InternalMessage::default()
                    };
                    events.push(MessageEvent {
                        t: EventType::VoteVerified,
                        input: msg,
                        err: None,
                        ..MessageEvent::default()
                    });

                    // Record the participation action.
                    self.keys.record(
                        &vote.raw_vote.sender,
                        vote.raw_vote.round,
                        ParticipationAction::Voted,
                    );
                }
                Err(_) => {
                    // This is normal: the account was not selected by sortition.
                    continue;
                }
            }
        }

        Ok(events)
    }

    fn quit(&mut self) {
        self.quit.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// ProposalData — internal struct holding proposal creation results
// ---------------------------------------------------------------------------

/// Internal struct holding the results of proposal creation for a single
/// account. Pairs the unauthenticated proposal with its proposal value.
struct ProposalData {
    /// The unauthenticated proposal (block + seed proof + proposer metadata).
    unauthenticated_proposal: UnauthenticatedProposal,
    /// The proposal value identifying this proposal.
    #[allow(dead_code)]
    proposal_value: ProposalValue,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create a proposal for a block using the given account's VRF key.
///
/// Mirrors Go's `proposalForBlock` in agreement/proposal.go.
///
/// This derives a new seed, finishes the block, and computes the proposal value.
fn proposal_for_block(
    address: &Address,
    _selection_id: &[u8; 32],
    unfinished_block: &dyn UnfinishedBlock,
    period: Period,
    ledger: &dyn LedgerReader,
) -> Result<(ProposalData, ProposalValue), PseudonodeError> {
    let rnd = unfinished_block.round();

    let cparams = ledger
        .consensus_params(lookback::params_round(rnd))
        .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    // Derive new seed. For the pseudonode we need the VRF secret key to
    // produce a seed proof, but the trait only gives us the public key.
    // In the Go code, `deriveNewSeed` uses the VRF secret to create a proof.
    // Since we don't have VRF secrets in ParticipationRecord (only public keys),
    // we create a placeholder seed derivation.
    //
    // NOTE: In a full implementation, `ParticipationRecord` would include VRF
    // secrets (or a signing interface) to produce the seed proof. For now, we
    // derive the seed from the previous round's seed when possible, matching
    // the structure of the Go code.
    let seed_rnd = lookback::seed_round(rnd, &cparams);
    let prev_seed = ledger
        .seed(seed_rnd)
        .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    // For period 0, seed is derived from proposer VRF output; for period > 0,
    // seed is derived from previous seed. Since we don't have VRF secrets to
    // produce a real proof, use the period > 0 path as a fallback.
    let new_seed = if period == Period(0) {
        // In a full implementation, we would call VRF.Prove(selector_message)
        // and use the output. For now, derive deterministically from the
        // previous seed and the proposer address.
        crate::seed::derive_seed_period_zero(
            address,
            // Use a deterministic placeholder VRF output derived from seed +
            // address (this will be replaced when VRF signing is available).
            &derive_placeholder_vrf_output(&prev_seed, address),
            None,
        )
    } else {
        crate::seed::derive_seed_period_nonzero(&prev_seed, None)
    };

    // Check payout eligibility.
    let eligible = check_payout_eligible(rnd, address, ledger, &cparams);

    // Finish the block.
    let block = unfinished_block.finish_block(new_seed, *address, eligible);

    // Compute proposal value.
    let block_digest = algo_codec::compute_block_digest(&block);
    let uprop = UnauthenticatedProposal {
        block,
        seed_proof: [0u8; 80], // Placeholder — real VRF proof would go here.
        original_period: period,
        original_proposer: *address,
    };

    let encoding_digest = crate::hashable::hash_obj(&uprop);

    let pv = ProposalValue {
        original_period: period,
        original_proposer: *address,
        block_digest,
        encoding_digest,
    };

    let proposal_data = ProposalData {
        unauthenticated_proposal: uprop,
        proposal_value: pv,
    };

    Ok((proposal_data, pv))
}

/// Create an unauthenticated vote from a raw vote and participation record.
///
/// Mirrors Go's `makeVote` in agreement/vote.go.
///
/// This looks up membership from the ledger, creates the VRF credential,
/// and signs the vote with the OTS key.
fn make_vote(
    rv: &RawVote,
    part: &ParticipationRecord,
    ledger: &dyn LedgerReader,
) -> Result<UnauthenticatedVote, PseudonodeError> {
    // Look up membership from ledger.
    let (_membership, _record, _cparams) = crate::ledger_reader::membership_from_ledger(
        ledger, &rv.sender, rv.round, rv.period, rv.step,
    )
    .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    let cparams = ledger
        .consensus_params(lookback::params_round(rv.round))
        .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    // Validate step/proposal constraints (matches Go's switch in makeVote).
    match rv.step {
        step if step == PROPOSE
            || step == crate::step::SOFT
            || step == crate::step::CERT
            || step == crate::step::LATE
            || step == crate::step::REDO =>
        {
            if rv.proposal.is_bottom() {
                return Err(PseudonodeError::VoteFailed(format!(
                    "votes from step {} cannot validate bottom",
                    rv.step
                )));
            }
        }
        step if step == crate::step::DOWN => {
            if !rv.proposal.is_bottom() {
                return Err(PseudonodeError::VoteFailed(format!(
                    "votes from step {} must validate bottom",
                    rv.step
                )));
            }
        }
        _ => {}
    }

    // Compute ephemeral key ID for OTS signing.
    let effective_kd =
        lookback::effective_key_dilution(part.vote_key_dilution, cparams.default_key_dilution);
    let _eph_id = algo_consensus_crypto::one_time_id_for_round(rv.round.0, effective_kd);

    // Sign the raw vote with OTS.
    // NOTE: In a full implementation, ParticipationRecord would contain the
    // OTS signing secrets. Since we only have the public verifier key, we
    // create a placeholder signature. The actual signing will use:
    //   let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
    //   let sig = ots_secrets.sign(&msg, rv.round.0, effective_kd);
    //
    // For now, produce a zero signature as a structural placeholder.
    let sig = algo_consensus_crypto::OneTimeSignature {
        sig: [0u8; 64],
        pk: [0u8; 32],
        pk_sig_old: [0u8; 64],
        pk2: [0u8; 32],
        pk1_sig: [0u8; 64],
        pk2_sig: [0u8; 64],
    };

    // Create VRF credential.
    // NOTE: In a full implementation, we would use VRF secrets to produce a
    // real proof:
    //   let vrf_message = hash_rep(&membership.selector);
    //   let (proof, _) = vrf_sk.prove(&vrf_message);
    // For now, use a placeholder proof.
    let cred = UnauthenticatedCredential::new([0u8; 80]);

    Ok(UnauthenticatedVote {
        raw_vote: rv.clone(),
        cred,
        sig,
    })
}

/// Verify a vote by looking up the necessary parameters from the ledger.
///
/// This is the synchronous equivalent of Go's async vote verification pipeline.
/// In Go, votes go through `AsyncVoteVerifier.verifyVote` which batches them.
/// Here we verify inline.
fn verify_vote_from_ledger(
    uv: &UnauthenticatedVote,
    ledger: &dyn LedgerReader,
) -> Result<crate::vote::Vote, PseudonodeError> {
    let rv = &uv.raw_vote;

    // Look up membership data from ledger.
    let (membership, record, cparams) = crate::ledger_reader::membership_from_ledger(
        ledger, &rv.sender, rv.round, rv.period, rv.step,
    )
    .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    let params = crate::vote::VoteVerifyParams {
        membership,
        vote_id: record.vote_id,
        vote_first_valid: record.vote_first_valid,
        vote_last_valid: record.vote_last_valid,
        vote_key_dilution: record.vote_key_dilution,
        consensus_params: cparams,
    };

    uv.verify(&params)
        .map_err(|e| PseudonodeError::VoteFailed(e.to_string()))
}

/// Check whether a proposer is eligible for block incentive payouts.
///
/// Mirrors Go's `payoutEligible` check. Returns true if the account is eligible.
fn check_payout_eligible(
    round: Round,
    address: &Address,
    ledger: &dyn LedgerReader,
    cparams: &algo_types::ConsensusParams,
) -> bool {
    // Attempt to use the existing payout_eligible function from proposal.rs.
    // If the ledger lookup fails, default to false.
    match crate::proposal::payout_eligible(round, address, ledger, cparams) {
        Ok((eligible, _record)) => eligible,
        Err(_) => false,
    }
}

/// Derive a placeholder VRF output from a seed and address.
///
/// This is a temporary helper used until real VRF signing is integrated into
/// the ParticipationRecord. It produces a deterministic 64-byte output by
/// hashing the seed and address together.
fn derive_placeholder_vrf_output(seed: &Seed, address: &Address) -> [u8; 64] {
    use sha2::{Digest as _, Sha512_256};

    let mut hasher = Sha512_256::new();
    hasher.update(seed.as_bytes());
    hasher.update(address.0);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha512_256::new();
    hasher2.update(hash1);
    hasher2.update(b"vrf-placeholder");
    let hash2 = hasher2.finalize();

    let mut output = [0u8; 64];
    output[..32].copy_from_slice(&hash1);
    output[32..].copy_from_slice(&hash2);
    output
}

/// Helper: construct a `SerializableError` from a `PseudonodeError`.
pub fn make_ser_err(err: &PseudonodeError) -> SerializableError {
    SerializableError::new(err.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;
    use crate::step::Period;
    use crate::traits::{ParticipationAction, ParticipationRecord};
    use crate::vote::BOTTOM;
    use algo_types::{Address, ConsensusParams, Digest, Round};
    use std::cell::RefCell;

    // -- Stubs for testing --

    struct TestKeyManager {
        keys: Vec<ParticipationRecord>,
        recorded: RefCell<Vec<(Address, Round, ParticipationAction)>>,
    }

    impl TestKeyManager {
        fn new(keys: Vec<ParticipationRecord>) -> Self {
            Self {
                keys,
                recorded: RefCell::new(Vec::new()),
            }
        }

        fn empty() -> Self {
            Self::new(Vec::new())
        }
    }

    impl AgreementKeyManager for TestKeyManager {
        fn voting_keys(
            &self,
            _voting_round: Round,
            _keys_round: Round,
        ) -> Vec<ParticipationRecord> {
            self.keys.clone()
        }

        fn record(&self, account: &Address, round: Round, action: ParticipationAction) {
            self.recorded.borrow_mut().push((*account, round, action));
        }
    }

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    // -- PseudonodeError tests --

    #[test]
    fn pseudonode_error_display_backlog_full_proposal() {
        let err = PseudonodeError::BacklogFull {
            round: Round(42),
            period: Period(1),
            step: None,
        };
        let s = format!("{err}");
        assert!(s.contains("unable to make proposal"));
        assert!(s.contains("42"));
    }

    #[test]
    fn pseudonode_error_display_backlog_full_vote() {
        let err = PseudonodeError::BacklogFull {
            round: Round(42),
            period: Period(1),
            step: Some(Step(2)),
        };
        let s = format!("{err}");
        assert!(s.contains("unable to make vote"));
    }

    #[test]
    fn pseudonode_error_display_no_votes() {
        let err = PseudonodeError::NoVotes;
        assert!(format!("{err}").contains("no valid participation keys"));
    }

    #[test]
    fn pseudonode_error_display_no_proposals() {
        let err = PseudonodeError::NoProposals;
        assert!(format!("{err}").contains("no valid participation keys"));
    }

    #[test]
    fn pseudonode_error_display_verifier_closed() {
        let err = PseudonodeError::VerifierClosedChannel;
        assert!(format!("{err}").contains("crypto verifier closed"));
    }

    #[test]
    fn pseudonode_error_display_shutdown() {
        let err = PseudonodeError::Shutdown;
        assert!(format!("{err}").contains("shut down"));
    }

    // -- AsyncPseudonode construction --

    #[test]
    fn async_pseudonode_new() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::empty();
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let pn = AsyncPseudonode::new(factory, keys, ledger);
        assert!(!pn.quit.load(Ordering::SeqCst));
    }

    // -- Quit --

    #[test]
    fn async_pseudonode_quit() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::empty();
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);
        pn.quit();
        assert!(pn.quit.load(Ordering::SeqCst));
    }

    #[test]
    fn async_pseudonode_double_quit() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::empty();
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);
        pn.quit();
        pn.quit(); // Should not panic.
        assert!(pn.quit.load(Ordering::SeqCst));
    }

    // -- make_proposals with no keys --

    #[test]
    fn make_proposals_no_keys_returns_error() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::empty();
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);

        let result = pn.make_proposals(Round(100), Period(0));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PseudonodeError::NoProposals);
    }

    // -- make_votes with no keys --

    #[test]
    fn make_votes_no_keys_returns_error() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::empty();
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);

        let result = pn.make_votes(Round(100), Period(0), Step(1), BOTTOM);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PseudonodeError::NoVotes);
    }

    // -- make_proposals after quit --

    #[test]
    fn make_proposals_after_quit_returns_shutdown() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::new(vec![ParticipationRecord {
            address: Address([0x42; 32]),
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 100,
        }]);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);
        pn.quit();

        let result = pn.make_proposals(Round(100), Period(0));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PseudonodeError::Shutdown);
    }

    // -- make_votes after quit --

    #[test]
    fn make_votes_after_quit_returns_shutdown() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = TestKeyManager::new(vec![ParticipationRecord {
            address: Address([0x42; 32]),
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 100,
        }]);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, keys, ledger);
        pn.quit();

        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x42; 32]),
            block_digest: Digest([0xaa; 32]),
            encoding_digest: Digest([0xbb; 32]),
        };
        let result = pn.make_votes(Round(100), Period(0), Step(1), pv);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), PseudonodeError::Shutdown);
    }

    // -- make_ser_err --

    #[test]
    fn make_ser_err_from_pseudonode_error() {
        let err = PseudonodeError::NoVotes;
        let ser = make_ser_err(&err);
        assert!(ser.0.contains("no valid participation keys"));
    }

    // -- derive_placeholder_vrf_output --

    #[test]
    fn placeholder_vrf_output_deterministic() {
        let seed = Seed([0xab; 32]);
        let addr = Address([0x42; 32]);
        let out1 = derive_placeholder_vrf_output(&seed, &addr);
        let out2 = derive_placeholder_vrf_output(&seed, &addr);
        assert_eq!(out1, out2);
    }

    #[test]
    fn placeholder_vrf_output_different_inputs() {
        let seed = Seed([0xab; 32]);
        let addr1 = Address([0x42; 32]);
        let addr2 = Address([0x43; 32]);
        let out1 = derive_placeholder_vrf_output(&seed, &addr1);
        let out2 = derive_placeholder_vrf_output(&seed, &addr2);
        assert_ne!(out1, out2);
    }

    // -- Constants --

    #[test]
    fn pseudonode_verification_backlog_is_32() {
        assert_eq!(PSEUDONODE_VERIFICATION_BACKLOG, 32);
    }

    #[test]
    fn max_output_wait_duration_is_2s() {
        assert_eq!(MAX_PSEUDONODE_OUTPUT_WAIT_DURATION, Duration::from_secs(2));
    }
}
