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

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use algo_consensus_crypto::vrf::VrfKeypair;
use algo_consensus_crypto::OneTimeSignatureSecrets;
use algo_types::{Address, Round};

use crate::credential::UnauthenticatedCredential;
use crate::events::{EventType, InternalMessage, MessageEvent, Proposal, SerializableError};
use crate::hashable::{hash_rep, Hashable};
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
    /// When `persist_state_done` is `Some`, the pseudonode waits for the
    /// persistence confirmation before returning votes, matching Go's pattern
    /// where persistence completes before votes are broadcast.
    ///
    /// Mirrors Go's `MakeVotes(ctx, round, period, step, proposalValue, persistStateDone)
    ///     (chan externalEvent, error)`.
    fn make_votes(
        &mut self,
        round: Round,
        period: Period,
        step: Step,
        proposal: ProposalValue,
        persist_state_done: Option<crossbeam_channel::Receiver<Result<(), String>>>,
    ) -> Result<Vec<MessageEvent>, PseudonodeError>;

    /// Direct the pseudonode to exit and clean up resources.
    ///
    /// Mirrors Go's `Quit()`.
    fn quit(&mut self);
}

// ---------------------------------------------------------------------------
// SigningKeys — per-account VRF + OTS secrets
// ---------------------------------------------------------------------------

/// Signing secrets for a single participation account.
///
/// This pairs a VRF keypair (for committee selection credentials) with OTS
/// secrets (for vote signing). When both are present, the pseudonode can
/// produce cryptographically valid proposals and votes.
///
/// In Go, these are carried inside `ParticipationRecord` (which embeds
/// `*crypto.VRFSecrets` and `*crypto.OneTimeSignatureSecrets`). In Rust,
/// we keep them separate from `ParticipationRecord` (which only has public
/// keys) to avoid requiring `Debug` on crypto secret types and to minimize
/// the blast radius of the change.
pub struct AccountSigningKeys {
    /// The VRF keypair for producing sortition proofs.
    pub vrf: VrfKeypair,
    /// The OTS secrets for producing vote signatures.
    pub ots: OneTimeSignatureSecrets,
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
    /// Statically-registered per-account signing keys (VRF + OTS secrets),
    /// keyed by address. Used as a fallback when the key manager doesn't supply
    /// per-round secrets (e.g. tests that inject keys directly). When an
    /// account's signing keys are present, the pseudonode produces
    /// cryptographically valid VRF proofs and OTS signatures; otherwise,
    /// placeholder values are used.
    signing_keys: HashMap<Address, AccountSigningKeys>,
    /// Per-round signing secrets loaded from the key manager alongside the
    /// public voting records (keyed by address, rebuilt each round in
    /// [`Self::load_round_participation_keys`]). Preferred over `signing_keys`
    /// so secrets track the public records across key validity-window
    /// boundaries / rotation (TASK-272). Empty when the key manager supplies
    /// none (then the static `signing_keys` fallback applies).
    round_signing_keys: HashMap<Address, AccountSigningKeys>,
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
            signing_keys: HashMap::new(),
            round_signing_keys: HashMap::new(),
        }
    }

    /// Register signing keys for an account.
    ///
    /// When signing keys are registered, the pseudonode will produce
    /// real VRF proofs and OTS signatures for that account instead of
    /// placeholder values.
    pub fn register_signing_keys(&mut self, address: Address, keys: AccountSigningKeys) {
        self.signing_keys.insert(address, keys);
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

        // Load per-round signing secrets for the same records, so signing
        // material tracks the public records across key validity-window
        // boundaries / rotation. The key manager returns `None` for accounts it
        // has no secrets for (e.g. test managers), leaving the static
        // `signing_keys` fallback to apply.
        let addresses: Vec<Address> = self.participation_keys.iter().map(|r| r.address).collect();
        self.round_signing_keys.clear();
        for address in addresses {
            if let Some(keys) = self
                .keys
                .signing_keys_for(&address, vote_round, balance_round)
            {
                self.round_signing_keys.insert(address, keys);
            }
        }

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
                // Go logs everything but ErrAssembleBlockRoundStale as an
                // error; a stale round is normal operation. Keep both
                // visible at debug so "the node never proposes" is
                // diagnosable without a source rebuild.
                debug!(round = round.0, period = period.0, error = %e,
                    "block assembly failed; not proposing this round");
                return (Vec::new(), Vec::new());
            }
        };

        let mut votes = Vec::with_capacity(accounts.len());
        let mut proposals = Vec::with_capacity(accounts.len());

        for acc in accounts {
            // Look up signing keys for this account: prefer the per-round
            // secrets from the key manager, falling back to statically-
            // registered keys.
            let signing = self
                .round_signing_keys
                .get(&acc.address)
                .or_else(|| self.signing_keys.get(&acc.address));

            // Create the proposal for this block/account.
            match proposal_for_block(
                &acc.address,
                &acc.selection_id,
                unfinished_block.as_ref(),
                period,
                &self.ledger,
                signing,
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

                    match make_vote(&rv, acc, &self.ledger, signing) {
                        Ok(uv) => {
                            proposals.push(proposal);
                            votes.push(uv);
                        }
                        Err(e) => {
                            // Go logs this as a warning and continues. The
                            // overwhelmingly common cause is "this account
                            // was not selected as a proposer this round".
                            debug!(round = round.0, period = period.0,
                                account = ?acc.address, error = %e,
                                "no proposal vote for account");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // Go logs this as an error and continues. Unlike the
                    // make_vote path this is never routine — it means the
                    // ledger could not supply the seed / consensus params
                    // needed to build a proposal at all.
                    warn!(round = round.0, period = period.0,
                        account = ?acc.address, error = %e,
                        "could not build a proposal for account");
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

            let signing = self
                .round_signing_keys
                .get(&part.address)
                .or_else(|| self.signing_keys.get(&part.address));
            match make_vote(&rv, part, &self.ledger, signing) {
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
                                // Pseudonode proposals don't carry a pre-validated block,
                                // matching Go's makeProposalFromProposableBlock which sets
                                // ve to nil. Self-proposed blocks will take the
                                // ensure_block path rather than ensure_validated_block.
                                validated_block: None,
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
        persist_state_done: Option<crossbeam_channel::Receiver<Result<(), String>>>,
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

        // Wait for persistence to complete before generating votes, matching
        // Go's pattern where persistence must finish before votes are broadcast.
        // If persistence fails, drop votes to prevent double-voting after crash
        // (matches Go behavior in asyncPseudonode.makeVotes).
        if let Some(rx) = persist_state_done {
            match rx.recv() {
                Ok(Ok(())) => {
                    // Persistence succeeded — proceed with vote generation.
                }
                Ok(Err(e)) => {
                    // Persistence failed — drop votes to prevent double-voting.
                    tracing::warn!("persistence failed, dropping votes: {}", e);
                    return Ok(vec![]);
                }
                Err(_) => {
                    // Channel disconnected — persistence loop crashed.
                    tracing::warn!("persistence channel disconnected, dropping votes");
                    return Ok(vec![]);
                }
            }
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

/// The optional `History` term folded into `seedInput` when the round
/// falls in a seed re-randomization window.
///
/// Mirrors the shared tail of Go's `deriveNewSeed` and `verifyProposer`
/// (`../go-algorand/agreement/proposal.go`):
///
/// ```go
/// rerand := rnd % basics.Round(cparams.SeedLookback*cparams.SeedRefreshInterval)
/// if rerand < basics.Round(cparams.SeedLookback) {
///     digrnd := rnd.SubSaturate(basics.Round(cparams.SeedLookback * cparams.SeedRefreshInterval))
///     input.History, err = ledger.LookupDigest(digrnd)
/// }
/// ```
///
/// Returns `None` outside those windows, which is the overwhelming
/// majority of rounds (8 in every 640 under ConsensusFuture).
fn seed_history(
    rnd: Round,
    cparams: &algo_types::ConsensusParams,
    ledger: &dyn LedgerReader,
) -> Result<Option<algo_types::Digest>, PseudonodeError> {
    let interval = cparams.seed_lookback * cparams.seed_refresh_interval;
    if interval == 0 || rnd.0 % interval >= cparams.seed_lookback {
        return Ok(None);
    }
    let digrnd = rnd.sub_saturate(interval);
    let digest = ledger.lookup_digest(digrnd).map_err(|e| {
        PseudonodeError::LedgerError(format!(
            "could not lookup old entry digest (for seed) from round {}: {e}",
            digrnd.0
        ))
    })?;
    Ok(Some(digest))
}

/// Create a proposal for a block using the given account's VRF key.
///
/// Mirrors Go's `proposalForBlock` in agreement/proposal.go.
///
/// This derives a new seed, finishes the block, and computes the proposal value.
/// When `signing_keys` is provided, real VRF proofs are generated; otherwise
/// placeholder values are used.
fn proposal_for_block(
    address: &Address,
    _selection_id: &[u8; 32],
    unfinished_block: &dyn UnfinishedBlock,
    period: Period,
    ledger: &dyn LedgerReader,
    signing_keys: Option<&AccountSigningKeys>,
) -> Result<(ProposalData, ProposalValue), PseudonodeError> {
    let rnd = unfinished_block.round();

    let cparams = ledger
        .consensus_params(lookback::params_round(rnd))
        .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    let seed_rnd = lookback::seed_round(rnd, &cparams);
    let prev_seed = ledger
        .seed(seed_rnd)
        .map_err(|e| PseudonodeError::LedgerError(e.to_string()))?;

    // Every `SeedRefreshInterval * SeedLookback` rounds the seed is
    // re-randomized with an old block digest. Go's `deriveNewSeed` folds
    // that `History` term into `seedInput` and `verifyProposer` recomputes
    // it the same way, so a proposer that always passes `None` produces a
    // block whose seed the network rejects on those rounds.
    let history = seed_history(rnd, &cparams, ledger)?;

    // Derive new seed and VRF proof.
    let (new_seed, seed_proof) = if period == Period(0) {
        if let Some(keys) = signing_keys {
            // Real VRF. Go's `deriveNewSeed` proves over the PREVIOUS
            // SEED itself — `vrf.SK.Prove(prevSeed)`, i.e. the VRF alpha
            // is `hashRep(prevSeed)` = "SD" || prevSeed — and
            // `verifyProposer` checks it with
            // `proposerRecord.SelectionID.Verify(p.SeedProof, prevSeed)`
            // (../go-algorand/agreement/proposal.go). Proving over the
            // sortition `Selector` instead makes every proposal we emit
            // fail Go's check with "seed proof malformed", which is
            // exactly what the 3-Go + 1-Rust cluster observed before
            // issue #469.
            let vrf_message = hash_rep(&prev_seed);
            let (proof, output) = keys.vrf.sk.prove(&vrf_message);

            let seed = crate::seed::derive_seed_period_zero(address, output.as_bytes(), history);
            (seed, *proof.as_bytes())
        } else {
            // Placeholder VRF: derive deterministically from seed + address.
            let vrf_out = derive_placeholder_vrf_output(&prev_seed, address);
            let seed = crate::seed::derive_seed_period_zero(address, &vrf_out, history);
            (seed, [0u8; 80])
        }
    } else {
        // Period > 0: seed is derived from previous seed, no VRF needed.
        let seed = crate::seed::derive_seed_period_nonzero(&prev_seed, history);
        (seed, [0u8; 80])
    };

    // Check payout eligibility.
    let eligible = check_payout_eligible(rnd, address, ledger, &cparams);

    // Finish the block.
    let block = unfinished_block.finish_block(new_seed, *address, eligible);

    // Compute proposal value.
    let block_digest = algo_codec::compute_block_digest(&block);
    let uprop = UnauthenticatedProposal {
        block,
        seed_proof,
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
/// and signs the vote with the OTS key. When `signing_keys` is provided,
/// real cryptographic signatures are produced; otherwise placeholder values
/// are used.
fn make_vote(
    rv: &RawVote,
    part: &ParticipationRecord,
    ledger: &dyn LedgerReader,
    signing_keys: Option<&AccountSigningKeys>,
) -> Result<UnauthenticatedVote, PseudonodeError> {
    // Look up membership from ledger.
    let (membership, _record, _cparams) = crate::ledger_reader::membership_from_ledger(
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
        step if step == crate::step::DOWN && !rv.proposal.is_bottom() => {
            return Err(PseudonodeError::VoteFailed(format!(
                "votes from step {} must validate bottom",
                rv.step
            )));
        }
        _ => {}
    }

    // Compute ephemeral key ID for OTS signing.
    let effective_kd =
        lookback::effective_key_dilution(part.vote_key_dilution, cparams.default_key_dilution);

    // Sign the raw vote with OTS and create VRF credential.
    let (sig, cred) = if let Some(keys) = signing_keys {
        // Real OTS signing: domain-separated message = hash_id || canonical(rawVote).
        let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
        let ots_sig = keys.ots.sign(&msg, rv.round.0, effective_kd);

        // Real VRF credential: VRF.Prove(hashRep(selector)) using the
        // membership's selector.
        let vrf_message = hash_rep(&membership.selector);
        let (proof, _output) = keys.vrf.sk.prove(&vrf_message);
        let vrf_cred = UnauthenticatedCredential::new(*proof.as_bytes());

        (ots_sig, vrf_cred)
    } else {
        // Placeholder: zero signature and zero VRF proof.
        let placeholder_sig = algo_consensus_crypto::OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        };
        let placeholder_cred = UnauthenticatedCredential::new([0u8; 80]);
        (placeholder_sig, placeholder_cred)
    };

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

        let result = pn.make_votes(Round(100), Period(0), Step(1), BOTTOM, None);
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
        let result = pn.make_votes(Round(100), Period(0), Step(1), pv, None);
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

    // ----------------------------------------------------------------------
    // Ports from go-algorand v4.6.0-stable agreement/pseudonode_test.go.
    //
    // TASK-65 (PLAN-31 §3.15). The Go test file has three top-level tests:
    //
    //   * `TestPseudonode` — exercises backlog overflow (bounded async
    //     verification queue), single-request event counts, and async-vs-
    //     serialized-pseudonode output equivalence.
    //   * `TestPseudonodeLoadingOfParticipationKeys` — caching + reload
    //     semantics of `asyncPseudonode.loadRoundParticipationKeys`, and
    //     proxy-based assertion that `KeyManager.VotingKeys` is called with
    //     the correct `(votingRound, balanceRound)` pair.
    //   * `TestPseudonodeNonEnqueuedTasks` — verifies graceful warn-and-
    //     continue when the async vote verifier's exec pool is full.
    //
    // ## Scenarios ported here
    // * Initial state of `participation_keys` and `participation_keys_round`.
    // * Cache hit on repeated `load_round_participation_keys(r)` (same r).
    // * Cache invalidation when the round changes.
    // * Proxy-based verification that `voting_keys` is called with the
    //   correct `(voting_round, balance_round)` pair across several
    //   rounds, matching Go's `KeyManagerProxy` scenario at lines 445-455.
    //
    // ## Scenarios intentionally NOT ported
    // * **Backlog overflow** (`pseudonodeVerificationBacklog*2` loop
    //   returning `errPseudonodeBacklogFull`) — Rust's `AsyncPseudonode`
    //   produces events synchronously inside `make_proposals` /
    //   `make_votes`, so there is no bounded pre-verification queue to
    //   overflow. The error variant `PseudonodeError::BacklogFull` is
    //   already constructed + displayed in the existing error tests
    //   above; the backlog integration path belongs to the crypto
    //   verifier tests, not the pseudonode.
    // * **`serializedPseudonode` equivalence** — Rust does not have a
    //   synchronous serialization wrapper type.
    // * **`TestPseudonodeNonEnqueuedTasks`** — depends on the async vote
    //   verifier exec pool and its log output; covered separately by the
    //   crypto_verifier tests.
    // * **Event-shape happy path** (Go lines 196-232: `make_proposals`
    //   returning `VoteVerified`+`PayloadVerified` pairs, `make_votes`
    //   returning only `VoteVerified`) — requires a full fixture stack
    //   (seeded block factory, online-account ledger entries, per-round
    //   seeds, registered VRF+OTS signing keys) so the pseudonode can
    //   produce credentials and signatures that verify. Without that,
    //   the tests pass vacuously on empty event lists and miss the
    //   regressions they would otherwise catch. Deferred to follow-up
    //   alongside the simulate / player-permutation infrastructure
    //   (DOC-21 §3.4 / §3.6) which builds the same stack.
    // * **`participationKeys = nil` retention** (Go test lines 432-436):
    //   the Go test relies on `nil` vs empty-slice distinction to verify
    //   that clearing `participationKeys` is NOT re-populated on a
    //   subsequent call with the same round. Rust's cache check
    //   `participation_keys_round == vote_round && !participation_keys
    //   .is_empty()` intentionally reloads when the cache is empty —
    //   making this a Rust-specific behavior divergence that is safer
    //   than the Go semantics (no risk of running with a mysteriously
    //   empty cache).
    //
    // The four ported scenarios together cover the portion of the Go
    // test file that maps onto the Rust API surface.

    /// Proxy KeyManager that captures every call to `voting_keys` so
    /// tests can assert the arguments the pseudonode passes in. Mirrors
    /// Go's `KeyManagerProxy` (pseudonode_test.go:385-398).
    struct RecordingKeyManager {
        inner_keys: Vec<ParticipationRecord>,
        calls: RefCell<Vec<(Round, Round)>>,
    }

    impl RecordingKeyManager {
        fn new(keys: Vec<ParticipationRecord>) -> Self {
            Self {
                inner_keys: keys,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(Round, Round)> {
            self.calls.borrow().clone()
        }
    }

    impl AgreementKeyManager for RecordingKeyManager {
        fn voting_keys(&self, voting_round: Round, keys_round: Round) -> Vec<ParticipationRecord> {
            self.calls.borrow_mut().push((voting_round, keys_round));
            self.inner_keys.clone()
        }

        fn record(&self, _account: &Address, _round: Round, _action: ParticipationAction) {}
    }

    fn participation_record(addr_byte: u8) -> ParticipationRecord {
        ParticipationRecord {
            address: Address([addr_byte; 32]),
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: Round(0),
            vote_last_valid: Round(1_000_000),
            vote_key_dilution: 100,
        }
    }

    /// Go test: `TestPseudonodeLoadingOfParticipationKeys`
    /// lines 423-425 ("verify start condition").
    #[test]
    fn load_round_participation_keys_initial_state_is_empty() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = RecordingKeyManager::new(vec![participation_record(1)]);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let pn = AsyncPseudonode::new(factory, keys, ledger);

        assert_eq!(pn.participation_keys_round, Round(0));
        assert!(pn.participation_keys.is_empty());
    }

    /// Go test lines 427-430 ("check after round 1"). First
    /// `load_round_participation_keys(Round(1))` populates the cache
    /// and updates `participation_keys_round`.
    #[test]
    fn load_round_participation_keys_populates_cache_on_first_call() {
        let factory = crate::stubs::StubBlockFactory::new();
        let key_manager =
            RecordingKeyManager::new(vec![participation_record(1), participation_record(2)]);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, key_manager, ledger);

        let loaded = pn.load_round_participation_keys(Round(1)).to_vec();
        assert_eq!(pn.participation_keys_round, Round(1));
        assert_eq!(loaded.len(), 2);
        // `ParticipationRecord` doesn't implement `PartialEq` (and we
        // don't want to add it in a test-only port), so compare the
        // stable-identity field (`address`) pointwise.
        let loaded_addrs: Vec<_> = loaded.iter().map(|r| r.address).collect();
        let cached_addrs: Vec<_> = pn.participation_keys.iter().map(|r| r.address).collect();
        assert_eq!(loaded_addrs, cached_addrs);
        assert_eq!(pn.keys.calls().len(), 1);

        // Cache hit: a second call with the SAME round must not re-invoke
        // `voting_keys` on the underlying KeyManager. This is the core of
        // Go's "check that participationKeysRound is preserved" assertion
        // at pseudonode_test.go:429-430 — without it, a regression that
        // re-fetches keys on every call would still pass the populate
        // check above. Mirrors Go test lines 432-435 (cache-keep
        // semantics) modulo the documented divergence on the
        // `participationKeys = nil` retention edge case.
        let _reloaded = pn.load_round_participation_keys(Round(1));
        assert_eq!(
            pn.keys.calls().len(),
            1,
            "second load with same round must hit cache, not re-invoke voting_keys",
        );
        assert_eq!(pn.participation_keys_round, Round(1));
    }

    /// Go test lines 438-442 ("check that it's being updated when asked
    /// with a different round number"). Changing the round triggers a
    /// reload.
    #[test]
    fn load_round_participation_keys_reloads_on_different_round() {
        let factory = crate::stubs::StubBlockFactory::new();
        let key_manager = RecordingKeyManager::new(vec![participation_record(7)]);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, key_manager, ledger);

        let _ = pn.load_round_participation_keys(Round(1));
        assert_eq!(pn.keys.calls().len(), 1);

        let loaded2 = pn.load_round_participation_keys(Round(2)).to_vec();
        assert_eq!(pn.participation_keys_round, Round(2));
        let loaded_addrs: Vec<_> = loaded2.iter().map(|r| r.address).collect();
        let cached_addrs: Vec<_> = pn.participation_keys.iter().map(|r| r.address).collect();
        assert_eq!(loaded_addrs, cached_addrs);
        // voting_keys must have been called a second time for the new round.
        assert_eq!(pn.keys.calls().len(), 2);
    }

    /// Go test lines 444-455: use a proxy to verify `voting_keys` is
    /// invoked with the correct `(voting_round, balance_round)` pair.
    /// `balance_round` is derived from consensus params; for our v41
    /// stub it's `voting_round - params.SeedLookback * params.SeedRefreshInterval`.
    #[test]
    fn load_round_participation_keys_calls_voting_keys_with_correct_balance_round() {
        let factory = crate::stubs::StubBlockFactory::new();
        let keys = vec![participation_record(5)];
        let key_manager = RecordingKeyManager::new(keys);
        let ledger = crate::stubs::StubLedger::new(v41_params(), Round(100));
        let mut pn = AsyncPseudonode::new(factory, key_manager, ledger);

        let cparams = v41_params();

        // Go walks rnd = 3..1000 step 43. Mirror the same cadence so any
        // lookback edge case (round boundaries, saturation to zero) is
        // exercised identically.
        let mut rnd = Round(3);
        while rnd.0 < 1000 {
            let _ = pn.load_round_participation_keys(rnd);
            let calls = pn.keys.calls();
            let (captured_voting, captured_balance) = *calls.last().expect("at least one call");
            assert_eq!(captured_voting, rnd, "voting_round mismatch at {rnd:?}");
            assert_eq!(
                captured_balance,
                crate::lookback::balance_round(rnd, &cparams),
                "balance_round mismatch at voting_round {rnd:?}",
            );
            rnd = Round(rnd.0 + 43);
        }
    }

    // Go test scenarios at lines 196-212 (`make_proposals` returns
    // `VoteVerified` + `PayloadVerified` pairs) and 214-232 (`make_votes`
    // returns only `VoteVerified`) would need a full happy-path fixture
    // to be meaningful: a seeded `StubBlockFactory::set_block`, per-round
    // `StubLedger::set_account` entries with online stake (so
    // `membership_from_ledger` succeeds), per-round seeds, and registered
    // `AccountSigningKeys` (VRF + OTS) so the pseudonode can produce
    // credentials and signatures that `verify_vote_from_ledger` accepts.
    // Without all of that, `assemble_block` returns `RoundStale` and
    // `create_proposals` / `create_votes` exit before emitting anything —
    // so an "events-empty-is-acceptable" assertion would pass vacuously
    // and miss the exact regressions the test is supposed to catch.
    //
    // Building that fixture stack is out of scope for this test-port task
    // (TASK-65 is sized "s"); it is a natural follow-up under the
    // player-permutation / simulate work in DOC-21 §3.4 / §3.6, which
    // brings the same infrastructure in for the broader state-machine
    // test matrix. See the top-of-block "Scenarios intentionally NOT
    // ported" list — this entry is captured there.

    // -- Seed derivation / seed proof (issue #469) ----------------------
    //
    // Regression tests for the bug the 3-Go + 1-Rust mixed cluster
    // surfaced: every Rust-proposed block was rejected by all three Go
    // nodes with `rejected block for (R, 0): ... seed proof malformed`,
    // because `proposal_for_block` proved the seed VRF over the sortition
    // `Selector` instead of over the previous seed. Go's `verifyProposer`
    // checks `SelectionID.Verify(p.SeedProof, prevSeed)`
    // (../go-algorand/agreement/proposal.go), so the two never matched.

    fn seeded_ledger(prev_seed: Seed, rnd: Round) -> crate::stubs::StubLedger {
        let cparams = v41_params();
        let mut ledger = crate::stubs::StubLedger::new(cparams.clone(), Round(rnd.0 + 1));
        ledger
            .seeds
            .insert(crate::lookback::seed_round(rnd, &cparams), prev_seed);
        ledger
    }

    /// The proof a proposer emits must verify under Go's rule: the VRF
    /// alpha is `hashRep(prevSeed)`, not the sortition selector.
    #[test]
    fn proposal_seed_proof_verifies_against_previous_seed() {
        let rnd = Round(100);
        let prev_seed = Seed([0x5a; 32]);
        let ledger = seeded_ledger(prev_seed, rnd);
        let address = Address([0x11; 32]);
        let keys = AccountSigningKeys {
            vrf: VrfKeypair::from_seed([7u8; 32]),
            ots: OneTimeSignatureSecrets::generate(0, 4),
        };
        let ub = crate::stubs::StubUnfinishedBlock::new(algo_types::Block::default(), rnd);

        let (data, _pv) = proposal_for_block(
            &address,
            keys.vrf.pk.as_bytes(),
            &ub,
            Period(0),
            &ledger,
            Some(&keys),
        )
        .expect("proposal_for_block");

        // Go: verifier.Verify(p.SeedProof, prevSeed)
        let proof = algo_consensus_crypto::vrf::VrfProof(data.unauthenticated_proposal.seed_proof);
        let vrf_out = keys
            .vrf
            .pk
            .verify(&proof, &hash_rep(&prev_seed))
            .expect("seed proof must verify over hash_rep(prev_seed)");

        // ... and the seed handed to finish_block must be the one derived
        // from that same proof's output.
        let finish_args = *ub.finish_args.borrow();
        let (seed, proposer, _eligible) = finish_args.expect("finish_block was called");
        assert_eq!(proposer, address);
        assert_eq!(
            seed,
            crate::seed::derive_seed_period_zero(&address, &vrf_out.0, None)
        );
    }

    /// Proving over the sortition selector — the pre-#469 behaviour — must
    /// NOT verify, so this test fails if the old input is reintroduced.
    #[test]
    fn selector_derived_seed_proof_does_not_verify() {
        let rnd = Round(100);
        let prev_seed = Seed([0x5a; 32]);
        let keys = AccountSigningKeys {
            vrf: VrfKeypair::from_seed([7u8; 32]),
            ots: OneTimeSignatureSecrets::generate(0, 4),
        };
        let selector = crate::selector::Selector {
            seed: prev_seed,
            round: rnd,
            period: Period(0),
            step: PROPOSE,
        };
        let (proof, _) = keys.vrf.sk.prove(&hash_rep(&selector));
        assert!(
            keys.vrf.pk.verify(&proof, &hash_rep(&prev_seed)).is_none(),
            "a selector-derived proof must not satisfy Go's prevSeed check"
        );
    }

    /// Outside a re-randomization window there is no History term, and the
    /// ledger is never consulted for an old digest.
    #[test]
    fn seed_history_is_none_outside_rerand_window() {
        let cparams = v41_params();
        let interval = cparams.seed_lookback * cparams.seed_refresh_interval;
        // An empty StubLedger errors on every lookup_digest, so a None
        // result also proves no lookup was attempted.
        let ledger = crate::stubs::StubLedger::new(cparams.clone(), Round(1));
        let rnd = Round(interval + cparams.seed_lookback);
        assert_eq!(seed_history(rnd, &cparams, &ledger).unwrap(), None);
    }

    /// Inside the window the History term is the digest of the round
    /// exactly one full interval back.
    #[test]
    fn seed_history_reads_old_digest_inside_rerand_window() {
        let cparams = v41_params();
        let interval = cparams.seed_lookback * cparams.seed_refresh_interval;
        let rnd = Round(2 * interval + 1);
        let digrnd = Round(interval + 1);
        let mut ledger = crate::stubs::StubLedger::new(cparams.clone(), Round(rnd.0 + 1));
        ledger.digests.insert(digrnd, Digest([0xc3; 32]));
        assert_eq!(
            seed_history(rnd, &cparams, &ledger).unwrap(),
            Some(Digest([0xc3; 32]))
        );
    }

    /// Error path: inside the window with no digest on file, the proposer
    /// must surface a ledger error rather than silently dropping History
    /// and proposing a block the network will reject.
    #[test]
    fn seed_history_propagates_missing_digest_error() {
        let cparams = v41_params();
        let interval = cparams.seed_lookback * cparams.seed_refresh_interval;
        let rnd = Round(2 * interval + 1);
        let ledger = crate::stubs::StubLedger::new(cparams.clone(), Round(rnd.0 + 1));
        let err = seed_history(rnd, &cparams, &ledger).unwrap_err();
        match err {
            PseudonodeError::LedgerError(msg) => {
                assert!(
                    msg.contains("old entry digest"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected LedgerError, got {other:?}"),
        }
    }
}
