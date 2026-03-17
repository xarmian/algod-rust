// Event types for the agreement protocol state machine.
//
// Mirrors go-algorand/agreement/events.go.
//
// Every event type from the Go implementation is represented here. The Go
// `event` interface is modeled as the `Event` enum, with each variant wrapping
// the corresponding event struct.

use std::fmt;
use std::time::Duration;

use algo_types::Round;

use crate::bundle::UnauthenticatedBundle;
use crate::proposal::UnauthenticatedProposal;
use crate::step::{Period, Step};
use crate::vote::{ProposalValue, RawVote, UnauthenticatedVote, Vote, BOTTOM};

// ---------------------------------------------------------------------------
// EventType
// ---------------------------------------------------------------------------

/// Identifies the particular type of event emitted by or delivered to a state
/// machine.
///
/// Mirrors Go's `eventType` enum in agreement/events.go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventType {
    /// No event.
    #[default]
    None = 0,

    // -- External input events -----------------------------------------------
    /// A vote has been received from the network (unverified).
    VotePresent,
    /// A payload (proposal) has been received from the network (unverified).
    PayloadPresent,
    /// A bundle has been received from the network (unverified).
    BundlePresent,

    /// A vote has been cryptographically verified.
    VoteVerified,
    /// A payload has been cryptographically verified.
    PayloadVerified,
    /// A bundle has been cryptographically verified.
    BundleVerified,

    /// An external source observed that the current round completed.
    RoundInterruption,

    /// A filter/deadline timeout has fired.
    Timeout,
    /// A fast partition recovery timeout has fired.
    FastTimeout,

    // -- Internal threshold events -------------------------------------------
    /// Soft-vote threshold reached.
    SoftThreshold,
    /// Cert-vote threshold reached.
    CertThreshold,
    /// Next-vote threshold reached.
    NextThreshold,

    // -- Proposal events -----------------------------------------------------
    /// A proposal-value is committable.
    ProposalCommittable,
    /// A proposal-value was accepted.
    ProposalAccepted,

    // -- Filtered / malformed ------------------------------------------------
    /// A vote was filtered (irrelevant).
    VoteFiltered,
    /// A vote was malformed (corrupt).
    VoteMalformed,
    /// A bundle was filtered (irrelevant).
    BundleFiltered,
    /// A bundle was malformed (corrupt).
    BundleMalformed,
    /// A payload was rejected (irrelevant).
    PayloadRejected,
    /// A payload was malformed (corrupt).
    PayloadMalformed,

    // -- Payload processing --------------------------------------------------
    /// An unauthenticated payload was pipelined.
    PayloadPipelined,
    /// An authenticated payload was accepted.
    PayloadAccepted,

    // -- Proposal flow -------------------------------------------------------
    /// The proposal-vote with the lowest credential should be fixed.
    ProposalFrozen,
    /// A relevant vote has been validated and accepted by the voteMachine.
    VoteAccepted,

    /// A new round has started.
    NewRound,
    /// A new period has started.
    NewPeriod,

    // -- Query events --------------------------------------------------------
    /// Read the staging value for a period.
    ReadStaging,
    /// Read the pinned value.
    ReadPinned,
    /// Read the lowest-credential vote.
    ReadLowestVote,

    /// Internal: check for duplicate votes.
    VoteFilterRequest,
    /// Response to VoteFilterRequest.
    VoteFilteredStep,

    /// Request next-threshold status.
    NextThresholdStatusRequest,
    /// Response with next-threshold status.
    NextThresholdStatus,

    /// Request freshest bundle.
    FreshestBundleRequest,
    /// Response with freshest bundle.
    FreshestBundle,

    /// Request to dump votes.
    DumpVotesRequest,
    /// Response with dumped votes.
    DumpVotes,

    /// For testing purposes only.
    WrappedAction,

    /// Checkpoint has been persisted to disk.
    CheckpointReached,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::VotePresent => "votePresent",
            Self::PayloadPresent => "payloadPresent",
            Self::BundlePresent => "bundlePresent",
            Self::VoteVerified => "voteVerified",
            Self::PayloadVerified => "payloadVerified",
            Self::BundleVerified => "bundleVerified",
            Self::RoundInterruption => "roundInterruption",
            Self::Timeout => "timeout",
            Self::FastTimeout => "fastTimeout",
            Self::SoftThreshold => "softThreshold",
            Self::CertThreshold => "certThreshold",
            Self::NextThreshold => "nextThreshold",
            Self::ProposalCommittable => "proposalCommittable",
            Self::ProposalAccepted => "proposalAccepted",
            Self::VoteFiltered => "voteFiltered",
            Self::VoteMalformed => "voteMalformed",
            Self::BundleFiltered => "bundleFiltered",
            Self::BundleMalformed => "bundleMalformed",
            Self::PayloadRejected => "payloadRejected",
            Self::PayloadMalformed => "payloadMalformed",
            Self::PayloadPipelined => "payloadPipelined",
            Self::PayloadAccepted => "payloadAccepted",
            Self::ProposalFrozen => "proposalFrozen",
            Self::VoteAccepted => "voteAccepted",
            Self::NewRound => "newRound",
            Self::NewPeriod => "newPeriod",
            Self::ReadStaging => "readStaging",
            Self::ReadPinned => "readPinned",
            Self::ReadLowestVote => "readLowestVote",
            Self::VoteFilterRequest => "voteFilterRequest",
            Self::VoteFilteredStep => "voteFilteredStep",
            Self::NextThresholdStatusRequest => "nextThresholdStatusRequest",
            Self::NextThresholdStatus => "nextThresholdStatus",
            Self::FreshestBundleRequest => "freshestBundleRequest",
            Self::FreshestBundle => "freshestBundle",
            Self::DumpVotesRequest => "dumpVotesRequest",
            Self::DumpVotes => "dumpVotes",
            Self::WrappedAction => "wrappedAction",
            Self::CheckpointReached => "checkpointReached",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ConsensusVersionView
// ---------------------------------------------------------------------------

/// A view of the consensus version as read from a LedgerReader, associated
/// with some round.
///
/// Mirrors Go's `ConsensusVersionView`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsensusVersionView {
    /// Error encountered when looking up the consensus version (if any).
    pub err: Option<String>,
    /// The consensus version string (e.g. "v41").
    pub version: String,
}

// ---------------------------------------------------------------------------
// SerializableError
// ---------------------------------------------------------------------------

/// A serializable error string, matching Go's `serializableError`.
///
/// This is a simple newtype around `String` that can be serialized to cadaver
/// files (for debugging / autopsy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializableError(pub String);

impl fmt::Display for SerializableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SerializableError {}

impl SerializableError {
    /// Create a new `SerializableError` from the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// ---------------------------------------------------------------------------
// InternalMessage
// ---------------------------------------------------------------------------

/// An internal message passed between components of the agreement service.
///
/// Mirrors Go's `message` struct in agreement/message.go.
///
/// In Go, this carries authenticated + unauthenticated forms of votes,
/// proposals, and bundles. Here we use `Option` for the optional fields.
#[derive(Debug, Clone)]
pub struct InternalMessage {
    /// The protocol tag identifying the message type.
    pub tag: String,

    /// Authenticated vote (set after verification).
    pub vote: Option<Vote>,
    /// Authenticated proposal (set after verification).
    pub proposal: Option<Proposal>,
    /// Verified votes from a bundle (set after bundle verification).
    /// In Go, this is `e.Input.Bundle.Votes` plus the equivocation votes.
    pub verified_bundle_votes: Vec<Vote>,

    /// Unauthenticated vote.
    pub unauthenticated_vote: UnauthenticatedVote,
    /// Unauthenticated proposal.
    pub unauthenticated_proposal: UnauthenticatedProposal,
    /// Unauthenticated bundle.
    pub unauthenticated_bundle: UnauthenticatedBundle,

    /// Compound message (proposal-vote + proposal payload concatenated).
    pub compound_message: CompoundMessage,
}

/// Default for `InternalMessage` — all fields zeroed/empty.
impl Default for InternalMessage {
    fn default() -> Self {
        Self {
            tag: String::new(),
            vote: None,
            proposal: None,
            verified_bundle_votes: Vec::new(),
            unauthenticated_vote: UnauthenticatedVote::default(),
            unauthenticated_proposal: UnauthenticatedProposal::default(),
            unauthenticated_bundle: UnauthenticatedBundle::default(),
            compound_message: CompoundMessage::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Proposal (authenticated)
// ---------------------------------------------------------------------------

/// An authenticated proposal — a block along with everything needed to validate
/// it, plus an optional pre-validated block reference.
///
/// Mirrors Go's `proposal` struct in agreement/proposal.go.
///
/// Note: `UnauthenticatedProposal` is defined in the `proposal` module.
/// This struct wraps it with validation-time metadata.
#[derive(Debug, Clone)]
pub struct Proposal {
    /// The unauthenticated proposal that was verified.
    pub unauthenticated_proposal: UnauthenticatedProposal,
    /// Time at which this proposal was validated (relative to round zero).
    pub validated_at: Duration,
    /// Time at which this proposal was received (relative to round zero).
    pub received_at: Duration,
}

impl Default for Proposal {
    fn default() -> Self {
        Self {
            unauthenticated_proposal: UnauthenticatedProposal::default(),
            validated_at: Duration::ZERO,
            received_at: Duration::ZERO,
        }
    }
}

// ---------------------------------------------------------------------------
// CompoundMessage
// ---------------------------------------------------------------------------

/// A compound message concatenating a proposal-vote and a proposal payload.
///
/// Mirrors Go's `compoundMessage` in agreement/message.go.
#[derive(Debug, Clone, Default)]
pub struct CompoundMessage {
    /// The proposal-vote.
    pub vote: UnauthenticatedVote,
    /// The proposal payload.
    pub proposal: UnauthenticatedProposal,
}

// ---------------------------------------------------------------------------
// FreshnessData
// ---------------------------------------------------------------------------

/// Data bundled with a filterable message event for freshness computation.
///
/// Mirrors Go's `freshnessData` struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FreshnessData {
    /// The player's current round.
    pub player_round: Round,
    /// The player's current period.
    pub player_period: Period,
    /// The player's current step.
    pub player_step: Step,
    /// The player's last concluding step.
    pub player_last_concluding: Step,
}

// ---------------------------------------------------------------------------
// LateCredentialTrackingEffect
// ---------------------------------------------------------------------------

/// Indicates the impact of a filtered vote on the credential tracking system.
///
/// Mirrors Go's `LateCredentialTrackingEffect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum LateCredentialTrackingEffect {
    /// The filtered event would have no impact on credential tracking.
    #[default]
    NoLateCredentialTrackingImpact = 0,
    /// The filtered event could impact credential tracking and more processing
    /// (validation) may be required.
    UnverifiedLateCredentialForTracking = 1,
    /// The filtered event provides a new best credential for its round.
    VerifiedBetterLateCredentialForTracking = 2,
}

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

/// An empty event, returned when there is nothing to report.
///
/// Mirrors Go's `emptyEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmptyEvent;

/// A message event carrying a vote, payload, or bundle message.
///
/// Mirrors Go's `messageEvent`.
#[derive(Debug, Clone)]
pub struct MessageEvent {
    /// The event type: one of {vote,payload,bundle}{Present,Verified}.
    pub t: EventType,
    /// The internal message itself.
    pub input: InternalMessage,
    /// Error from cryptographic verification (if attempted and failed).
    pub err: Option<SerializableError>,
    /// Task index for tracking through crypto verification.
    pub task_index: u64,
    /// An optional tail message event (used to schedule processing proposal
    /// payloads after a matching proposal-vote).
    pub tail: Option<Box<MessageEvent>>,
    /// Whether the corresponding request was cancelled.
    pub cancelled: bool,
    /// Consensus version view for this event's round.
    pub proto: ConsensusVersionView,
}

impl Default for MessageEvent {
    fn default() -> Self {
        Self {
            t: EventType::None,
            input: InternalMessage::default(),
            err: None,
            task_index: 0,
            tail: None,
            cancelled: false,
            proto: ConsensusVersionView::default(),
        }
    }
}

impl MessageEvent {
    /// Returns the round for this message event, based on the message type.
    ///
    /// Mirrors Go's `messageEvent.ConsensusRound()`.
    pub fn consensus_round(&self) -> Round {
        match self.t {
            EventType::VotePresent | EventType::VoteVerified => {
                self.input.unauthenticated_vote.raw_vote.round
            }
            EventType::PayloadPresent | EventType::PayloadVerified => {
                self.input.unauthenticated_proposal.round()
            }
            EventType::BundlePresent | EventType::BundleVerified => {
                self.input.unauthenticated_bundle.round
            }
            _ => Round(0),
        }
    }

    /// Returns a copy of this event with the given consensus version attached.
    pub fn attach_consensus_version(mut self, v: ConsensusVersionView) -> Self {
        self.proto = v;
        self
    }
}

impl fmt::Display for MessageEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{T:{} Err:{:?}}}", self.t, self.err)
    }
}

/// A filterable message event — a `MessageEvent` bundled with freshness data.
///
/// Mirrors Go's `filterableMessageEvent`.
#[derive(Debug, Clone, Default)]
pub struct FilterableMessageEvent {
    /// The underlying message event.
    pub message_event: MessageEvent,
    /// Player data for freshness computation.
    pub freshness_data: FreshnessData,
}

/// A round interruption event — the player's current round has completed
/// externally.
///
/// Mirrors Go's `roundInterruptionEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundInterruptionEvent {
    /// The round the state machine should enter after processing this event.
    pub round: Round,
    /// Consensus version view.
    pub proto: ConsensusVersionView,
}

impl RoundInterruptionEvent {
    /// Returns the consensus round for this event.
    pub fn consensus_round(&self) -> Round {
        self.round
    }

    /// Returns a copy with the given consensus version attached.
    pub fn attach_consensus_version(mut self, v: ConsensusVersionView) -> Self {
        self.proto = v;
        self
    }
}

impl fmt::Display for RoundInterruptionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::RoundInterruption)
    }
}

/// A timeout event — a timeout has fired.
///
/// Mirrors Go's `timeoutEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TimeoutEvent {
    /// The event type: `Timeout` or `FastTimeout`.
    pub t: EventType,
    /// Random entropy for napping (recovery step selection).
    pub random_entropy: u64,
    /// The round for this timeout.
    pub round: Round,
    /// Consensus version view.
    pub proto: ConsensusVersionView,
}

impl TimeoutEvent {
    /// Returns the consensus round for this event.
    pub fn consensus_round(&self) -> Round {
        self.round
    }

    /// Returns a copy with the given consensus version attached.
    pub fn attach_consensus_version(mut self, v: ConsensusVersionView) -> Self {
        self.proto = v;
        self
    }
}

impl fmt::Display for TimeoutEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.t)
    }
}

/// Signals a new round has started.
///
/// Mirrors Go's `newRoundEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewRoundEvent;

impl fmt::Display for NewRoundEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::NewRound)
    }
}

/// Signals a new period has started, with the proposal-value to agree on.
///
/// Mirrors Go's `newPeriodEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPeriodEvent {
    /// The latest period.
    pub period: Period,
    /// The proposal-value the new period may want to agree on.
    pub proposal: ProposalValue,
}

impl Default for NewPeriodEvent {
    fn default() -> Self {
        Self {
            period: Period(0),
            proposal: BOTTOM,
        }
    }
}

impl fmt::Display for NewPeriodEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::NewPeriod)
    }
}

/// A read-lowest event: sent to read the lowest-credential vote for a period.
///
/// Mirrors Go's `readLowestEvent`.
#[derive(Debug, Clone)]
pub struct ReadLowestEvent {
    /// The event type (currently only `ReadLowestVote`).
    pub t: EventType,
    /// The round for the query.
    pub round: Round,
    /// The period for the query.
    pub period: Period,
    /// The lowest-credential vote (response).
    pub vote: Option<Vote>,
    /// The lowest-credential vote including late arrivals (response).
    pub lowest_including_late: Option<Vote>,
    /// Whether the `vote` field is filled.
    pub filled: bool,
    /// Whether the `lowest_including_late` field is filled.
    pub has_lowest_including_late: bool,
}

impl Default for ReadLowestEvent {
    fn default() -> Self {
        Self {
            t: EventType::ReadLowestVote,
            round: Round(0),
            period: Period(0),
            vote: None,
            lowest_including_late: None,
            filled: false,
            has_lowest_including_late: false,
        }
    }
}

impl fmt::Display for ReadLowestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {}", self.t, self.round, self.period)
    }
}

/// A vote-accepted event — a relevant vote has been validated.
///
/// Mirrors Go's `voteAcceptedEvent`.
#[derive(Debug, Clone)]
pub struct VoteAcceptedEvent {
    /// The accepted vote.
    pub vote: Vote,
    /// Consensus version for the vote's round.
    pub proto: String,
}

impl fmt::Display for VoteAcceptedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}\t{:?}\t{:?}",
            EventType::VoteAccepted,
            self.vote.raw_vote.step,
            self.vote.raw_vote.sender,
            self.vote.raw_vote.proposal.block_digest,
        )
    }
}

/// A proposal-accepted event — a proposal-value was accepted.
///
/// Mirrors Go's `proposalAcceptedEvent`.
#[derive(Debug, Clone)]
pub struct ProposalAcceptedEvent {
    /// The round in which the proposal was accepted.
    pub round: Round,
    /// The period in which the proposal was accepted.
    pub period: Period,
    /// The accepted proposal-value.
    pub proposal: ProposalValue,
    /// The proposal payload (if already received).
    pub payload: Option<Proposal>,
    /// Whether the payload has been received.
    pub payload_ok: bool,
}

impl Default for ProposalAcceptedEvent {
    fn default() -> Self {
        Self {
            round: Round(0),
            period: Period(0),
            proposal: BOTTOM,
            payload: None,
            payload_ok: false,
        }
    }
}

impl fmt::Display for ProposalAcceptedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?}",
            EventType::ProposalAccepted,
            self.proposal.block_digest,
        )
    }
}

/// A proposal-frozen event — the proposal-vote with the lowest credential
/// should be fixed.
///
/// Mirrors Go's `proposalFrozenEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalFrozenEvent {
    /// The frozen proposal-value.
    pub proposal: ProposalValue,
}

impl Default for ProposalFrozenEvent {
    fn default() -> Self {
        Self { proposal: BOTTOM }
    }
}

impl fmt::Display for ProposalFrozenEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::ProposalFrozen)
    }
}

/// A committable event — a proposal-value is committable.
///
/// Mirrors Go's `committableEvent`.
#[derive(Debug, Clone)]
pub struct CommittableEvent {
    /// The committable proposal-value.
    pub proposal: ProposalValue,
    /// The proposal-vote that authenticated the payload (if one exists).
    pub vote: Option<Vote>,
}

impl Default for CommittableEvent {
    fn default() -> Self {
        Self {
            proposal: BOTTOM,
            vote: None,
        }
    }
}

impl fmt::Display for CommittableEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::ProposalCommittable)
    }
}

/// A payload-processed event — a payload was rejected, pipelined, or accepted.
///
/// Mirrors Go's `payloadProcessedEvent`.
#[derive(Debug, Clone)]
pub struct PayloadProcessedEvent {
    /// The event type: `PayloadRejected`, `PayloadPipelined`, or
    /// `PayloadAccepted`.
    pub t: EventType,
    /// The round for which a payload has been processed.
    pub round: Round,
    /// The period interested in this payload.
    pub period: Period,
    /// Whether this is a pinned payload (if so, period will be 0).
    pub pinned: bool,
    /// The proposal-value corresponding to the payload.
    pub proposal: ProposalValue,
    /// The unauthenticated proposal payload that was pipelined.
    pub unauthenticated_payload: UnauthenticatedProposal,
    /// A proposal-vote that authenticated the payload (if one exists).
    pub vote: Option<Vote>,
    /// The reason the proposal payload was rejected (for `PayloadRejected`).
    pub err: Option<SerializableError>,
}

impl Default for PayloadProcessedEvent {
    fn default() -> Self {
        Self {
            t: EventType::None,
            round: Round(0),
            period: Period(0),
            pinned: false,
            proposal: BOTTOM,
            unauthenticated_payload: UnauthenticatedProposal::default(),
            vote: None,
            err: None,
        }
    }
}

impl fmt::Display for PayloadProcessedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.t == EventType::PayloadRejected {
            write!(
                f,
                "{}: {:?}; {:?}",
                self.t, self.err, self.proposal.block_digest,
            )
        } else {
            write!(f, "{}: {:?}", self.t, self.proposal.block_digest)
        }
    }
}

/// A filtered event — the result of filtering a vote, bundle, or payload.
///
/// Mirrors Go's `filteredEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilteredEvent {
    /// The event type: one of {proposal,vote,bundle}{Filtered,Malformed}.
    pub t: EventType,
    /// Impact of the filtered event on credential tracking.
    pub late_credential_tracking_note: LateCredentialTrackingEffect,
    /// The reason cryptographic verification failed (for malformed events).
    pub err: Option<SerializableError>,
}

impl fmt::Display for FilteredEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.t, self.err)
    }
}

/// A staging-value event — response to a `ReadStaging` query.
///
/// Mirrors Go's `stagingValueEvent`.
#[derive(Debug, Clone)]
pub struct StagingValueEvent {
    /// The round of the staging value.
    pub round: Round,
    /// The period of the staging value.
    pub period: Period,
    /// The staging value itself.
    pub proposal: ProposalValue,
    /// The payload, if one exists.
    pub payload: Option<Proposal>,
    /// Whether the staging value is committable.
    pub committable: bool,
}

impl Default for StagingValueEvent {
    fn default() -> Self {
        Self {
            round: Round(0),
            period: Period(0),
            proposal: BOTTOM,
            payload: None,
            committable: false,
        }
    }
}

impl fmt::Display for StagingValueEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?}",
            EventType::ReadStaging,
            self.proposal.block_digest
        )
    }
}

/// A pinned-value event — response to a `ReadPinned` query.
///
/// Mirrors Go's `pinnedValueEvent`.
#[derive(Debug, Clone)]
pub struct PinnedValueEvent {
    /// The round for the pinned value query.
    pub round: Round,
    /// The pinned value itself.
    pub proposal: ProposalValue,
    /// The payload, if one exists.
    pub payload: Option<Proposal>,
    /// Whether a payload was received for the pinned value.
    pub payload_ok: bool,
}

impl Default for PinnedValueEvent {
    fn default() -> Self {
        Self {
            round: Round(0),
            proposal: BOTTOM,
            payload: None,
            payload_ok: false,
        }
    }
}

impl fmt::Display for PinnedValueEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?}",
            EventType::ReadPinned,
            self.proposal.block_digest
        )
    }
}

/// A threshold event — a threshold of votes has been reached for a given step.
///
/// Mirrors Go's `thresholdEvent`.
#[derive(Debug, Clone)]
pub struct ThresholdEvent {
    /// The event type: `SoftThreshold`, `CertThreshold`, `NextThreshold`, or
    /// `None`.
    pub t: EventType,
    /// The round where the threshold was reached.
    pub round: Round,
    /// The period where the threshold was reached.
    pub period: Period,
    /// The step where the threshold was reached.
    pub step: Step,
    /// The proposal-value for which the threshold was reached.
    pub proposal: ProposalValue,
    /// A quorum of votes forming the threshold.
    pub bundle: UnauthenticatedBundle,
    /// Consensus version.
    pub proto: String,
}

impl Default for ThresholdEvent {
    fn default() -> Self {
        Self {
            t: EventType::None,
            round: Round(0),
            period: Period(0),
            step: Step(0),
            proposal: BOTTOM,
            bundle: UnauthenticatedBundle::default(),
            proto: String::new(),
        }
    }
}

impl ThresholdEvent {
    /// Produces a partial ordering on threshold events from the same round.
    ///
    /// Mirrors Go's `thresholdEvent.fresherThan()`.
    ///
    /// The ordering:
    /// - certThreshold events are fresher than all non-certThreshold events.
    /// - Events from a later period are fresher than events from an older period.
    /// - nextThreshold events are fresher than softThreshold events from the
    ///   same period.
    /// - nextThreshold events for bottom are fresher than nextThreshold events
    ///   for some other value.
    ///
    /// Precondition: `self.round == other.round` if neither is `None`.
    pub fn fresher_than(&self, other: &ThresholdEvent) -> bool {
        if self.t == EventType::None && other.t == EventType::None {
            return true;
        }
        if self.t == EventType::None {
            return false;
        }
        if other.t == EventType::None {
            return true;
        }

        assert_eq!(
            self.round, other.round,
            "round mismatch: {:?} != {:?}",
            self.round, other.round
        );

        // Validate both are threshold types
        assert!(
            matches!(
                self.t,
                EventType::SoftThreshold | EventType::CertThreshold | EventType::NextThreshold
            ),
            "bad event: {:?}",
            self.t
        );
        assert!(
            matches!(
                other.t,
                EventType::SoftThreshold | EventType::CertThreshold | EventType::NextThreshold
            ),
            "bad event: {:?}",
            other.t
        );

        if other.t == EventType::CertThreshold {
            return false;
        }

        match self.t {
            EventType::SoftThreshold => self.period > other.period,
            EventType::CertThreshold => true,
            EventType::NextThreshold => {
                if self.period > other.period {
                    return true;
                }
                if self.period < other.period {
                    return false;
                }
                if other.t == EventType::SoftThreshold {
                    return true;
                }
                // Both are nextThreshold, same period
                self.proposal == BOTTOM && other.proposal != BOTTOM
            }
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for ThresholdEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.t {
            EventType::None => write!(f, "{}", EventType::None),
            _ => write!(f, "{}: {:?}", self.t, self.proposal.block_digest),
        }
    }
}

/// A vote-filter-request event — check for duplicate votes.
///
/// Mirrors Go's `voteFilterRequestEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteFilterRequestEvent {
    /// The raw vote to check.
    pub raw_vote: RawVote,
}

impl fmt::Display for VoteFilterRequestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}\t{:?}\t{:?}",
            EventType::VoteFilterRequest,
            self.raw_vote.step,
            self.raw_vote.sender,
            self.raw_vote.proposal.block_digest,
        )
    }
}

/// A filtered-step event — response to a vote filter request.
///
/// Mirrors Go's `filteredStepEvent`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilteredStepEvent {
    /// The event type (VoteFilteredStep).
    pub t: EventType,
}

impl fmt::Display for FilteredStepEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.t)
    }
}

/// A next-threshold-status request event.
///
/// Mirrors Go's `nextThresholdStatusRequestEvent`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NextThresholdStatusRequestEvent;

impl fmt::Display for NextThresholdStatusRequestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::NextThresholdStatusRequest)
    }
}

/// A next-threshold-status event — response to a status request.
///
/// Contains two bits of information:
/// - `bottom`: true if saw a threshold for bottom
/// - `proposal`: set to non-bottom if saw a threshold for some proposal
///
/// Mirrors Go's `nextThresholdStatusEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NextThresholdStatusEvent {
    /// True if saw a next-vote bottom threshold.
    pub bottom: bool,
    /// Set to non-bottom if saw a next value threshold.
    pub proposal: ProposalValue,
}

impl fmt::Display for NextThresholdStatusEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::NextThresholdStatus)
    }
}

/// A freshest-bundle request event.
///
/// Mirrors Go's `freshestBundleRequestEvent`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FreshestBundleRequestEvent;

impl fmt::Display for FreshestBundleRequestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::FreshestBundleRequest)
    }
}

/// A freshest-bundle event — response to a freshest-bundle request.
///
/// Mirrors Go's `freshestBundleEvent`.
#[derive(Debug, Clone, Default)]
pub struct FreshestBundleEvent {
    /// True if any threshold event was seen.
    pub ok: bool,
    /// The freshest threshold event seen by a round machine.
    pub event: ThresholdEvent,
}

impl fmt::Display for FreshestBundleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ({})", EventType::FreshestBundle, self.event)
    }
}

/// A dump-votes request event.
///
/// Mirrors Go's `dumpVotesRequestEvent`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DumpVotesRequestEvent;

impl fmt::Display for DumpVotesRequestEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::DumpVotesRequest)
    }
}

/// A dump-votes event — response to a dump-votes request.
///
/// Mirrors Go's `dumpVotesEvent`.
#[derive(Debug, Clone, Default)]
pub struct DumpVotesEvent {
    /// The dumped votes.
    pub votes: Vec<UnauthenticatedVote>,
}

impl fmt::Display for DumpVotesEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::DumpVotes)
    }
}

/// A checkpoint event — a checkpoint has been persisted to disk.
///
/// Mirrors Go's `checkpointEvent`.
#[derive(Debug, Clone, Default)]
pub struct CheckpointEvent {
    /// Round at the checkpoint.
    pub round: Round,
    /// Period at the checkpoint.
    pub period: Period,
    /// Step at the checkpoint.
    pub step: Step,
    /// Error from persisting state (None on success).
    pub err: Option<SerializableError>,
}

impl CheckpointEvent {
    /// Returns the consensus round (always 0 per Go implementation).
    pub fn consensus_round(&self) -> Round {
        Round(0)
    }
}

impl fmt::Display for CheckpointEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", EventType::CheckpointReached)
    }
}

// ---------------------------------------------------------------------------
// Event (top-level enum)
// ---------------------------------------------------------------------------

/// The top-level event enum wrapping all event types.
///
/// This models Go's `event` interface with its `t() eventType` method.
/// Each variant corresponds to one of the Go event structs.
#[derive(Debug, Clone)]
pub enum Event {
    /// No event.
    Empty(EmptyEvent),
    /// A message event (vote/payload/bundle present or verified).
    Message(MessageEvent),
    /// A filterable message event (message + freshness data).
    FilterableMessage(FilterableMessageEvent),
    /// A round interruption event.
    RoundInterruption(RoundInterruptionEvent),
    /// A timeout event.
    Timeout(TimeoutEvent),
    /// A new round event.
    NewRound(NewRoundEvent),
    /// A new period event.
    NewPeriod(NewPeriodEvent),
    /// A read-lowest event.
    ReadLowest(ReadLowestEvent),
    /// A vote-accepted event.
    VoteAccepted(VoteAcceptedEvent),
    /// A proposal-accepted event.
    ProposalAccepted(ProposalAcceptedEvent),
    /// A proposal-frozen event.
    ProposalFrozen(ProposalFrozenEvent),
    /// A committable event.
    Committable(CommittableEvent),
    /// A payload-processed event.
    PayloadProcessed(PayloadProcessedEvent),
    /// A filtered event.
    Filtered(FilteredEvent),
    /// A staging-value event.
    StagingValue(StagingValueEvent),
    /// A pinned-value event.
    PinnedValue(PinnedValueEvent),
    /// A threshold event.
    Threshold(ThresholdEvent),
    /// A vote-filter-request event.
    VoteFilterRequest(VoteFilterRequestEvent),
    /// A filtered-step event.
    FilteredStep(FilteredStepEvent),
    /// A next-threshold-status request.
    NextThresholdStatusRequest(NextThresholdStatusRequestEvent),
    /// A next-threshold-status response.
    NextThresholdStatus(NextThresholdStatusEvent),
    /// A freshest-bundle request.
    FreshestBundleRequest(FreshestBundleRequestEvent),
    /// A freshest-bundle response.
    FreshestBundle(FreshestBundleEvent),
    /// A dump-votes request.
    DumpVotesRequest(DumpVotesRequestEvent),
    /// A dump-votes response.
    DumpVotes(DumpVotesEvent),
    /// A checkpoint event.
    Checkpoint(CheckpointEvent),
}

impl Event {
    /// Returns the `EventType` for this event.
    ///
    /// Mirrors Go's `event.t()`.
    pub fn event_type(&self) -> EventType {
        match self {
            Self::Empty(_) => EventType::None,
            Self::Message(e) => e.t,
            Self::FilterableMessage(e) => e.message_event.t,
            Self::RoundInterruption(_) => EventType::RoundInterruption,
            Self::Timeout(e) => e.t,
            Self::NewRound(_) => EventType::NewRound,
            Self::NewPeriod(_) => EventType::NewPeriod,
            Self::ReadLowest(e) => e.t,
            Self::VoteAccepted(_) => EventType::VoteAccepted,
            Self::ProposalAccepted(_) => EventType::ProposalAccepted,
            Self::ProposalFrozen(_) => EventType::ProposalFrozen,
            Self::Committable(_) => EventType::ProposalCommittable,
            Self::PayloadProcessed(e) => e.t,
            Self::Filtered(e) => e.t,
            Self::StagingValue(_) => EventType::ReadStaging,
            Self::PinnedValue(_) => EventType::ReadPinned,
            Self::Threshold(e) => e.t,
            Self::VoteFilterRequest(_) => EventType::VoteFilterRequest,
            Self::FilteredStep(e) => e.t,
            Self::NextThresholdStatusRequest(_) => EventType::NextThresholdStatusRequest,
            Self::NextThresholdStatus(_) => EventType::NextThresholdStatus,
            Self::FreshestBundleRequest(_) => EventType::FreshestBundleRequest,
            Self::FreshestBundle(_) => EventType::FreshestBundle,
            Self::DumpVotesRequest(_) => EventType::DumpVotesRequest,
            Self::DumpVotes(_) => EventType::DumpVotes,
            Self::Checkpoint(_) => EventType::CheckpointReached,
        }
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::Empty(EmptyEvent)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(_) => write!(f, "{}", EventType::None),
            Self::Message(e) => write!(f, "{e}"),
            Self::FilterableMessage(e) => write!(f, "{}", e.message_event),
            Self::RoundInterruption(e) => write!(f, "{e}"),
            Self::Timeout(e) => write!(f, "{e}"),
            Self::NewRound(e) => write!(f, "{e}"),
            Self::NewPeriod(e) => write!(f, "{e}"),
            Self::ReadLowest(e) => write!(f, "{e}"),
            Self::VoteAccepted(e) => write!(f, "{e}"),
            Self::ProposalAccepted(e) => write!(f, "{e}"),
            Self::ProposalFrozen(e) => write!(f, "{e}"),
            Self::Committable(e) => write!(f, "{e}"),
            Self::PayloadProcessed(e) => write!(f, "{e}"),
            Self::Filtered(e) => write!(f, "{e}"),
            Self::StagingValue(e) => write!(f, "{e}"),
            Self::PinnedValue(e) => write!(f, "{e}"),
            Self::Threshold(e) => write!(f, "{e}"),
            Self::VoteFilterRequest(e) => write!(f, "{e}"),
            Self::FilteredStep(e) => write!(f, "{e}"),
            Self::NextThresholdStatusRequest(e) => write!(f, "{e}"),
            Self::NextThresholdStatus(e) => write!(f, "{e}"),
            Self::FreshestBundleRequest(e) => write!(f, "{e}"),
            Self::FreshestBundle(e) => write!(f, "{e}"),
            Self::DumpVotesRequest(e) => write!(f, "{e}"),
            Self::DumpVotes(e) => write!(f, "{e}"),
            Self::Checkpoint(e) => write!(f, "{e}"),
        }
    }
}

/// Creates a zeroed event of a given type.
///
/// Mirrors Go's `zeroEvent`.
pub fn zero_event(t: EventType) -> Event {
    match t {
        EventType::None => Event::Empty(EmptyEvent),
        EventType::VotePresent
        | EventType::VoteVerified
        | EventType::PayloadPresent
        | EventType::PayloadVerified
        | EventType::BundlePresent
        | EventType::BundleVerified => Event::Message(MessageEvent::default()),
        EventType::RoundInterruption => Event::RoundInterruption(RoundInterruptionEvent::default()),
        EventType::Timeout | EventType::FastTimeout => Event::Timeout(TimeoutEvent::default()),
        EventType::NewRound => Event::NewRound(NewRoundEvent),
        EventType::NewPeriod => Event::NewPeriod(NewPeriodEvent::default()),
        EventType::VoteAccepted => Event::VoteAccepted(VoteAcceptedEvent {
            vote: Vote::default(),
            proto: String::new(),
        }),
        EventType::ProposalAccepted => Event::ProposalAccepted(ProposalAcceptedEvent::default()),
        EventType::ProposalFrozen => Event::ProposalFrozen(ProposalFrozenEvent::default()),
        EventType::ProposalCommittable => Event::Committable(CommittableEvent::default()),
        EventType::PayloadRejected | EventType::PayloadPipelined | EventType::PayloadAccepted => {
            Event::PayloadProcessed(PayloadProcessedEvent::default())
        }
        EventType::VoteFiltered | EventType::BundleFiltered => {
            Event::Filtered(FilteredEvent::default())
        }
        EventType::SoftThreshold | EventType::CertThreshold | EventType::NextThreshold => {
            Event::Threshold(ThresholdEvent::default())
        }
        EventType::CheckpointReached => Event::Checkpoint(CheckpointEvent::default()),
        EventType::ReadStaging => Event::StagingValue(StagingValueEvent::default()),
        EventType::ReadPinned => Event::PinnedValue(PinnedValueEvent::default()),
        EventType::ReadLowestVote => Event::ReadLowest(ReadLowestEvent::default()),
        _ => panic!("bad event type: {t}"),
    }
}

/// The timestamp assigned to messages that arrive for round R+1 while the
/// current player is still waiting for quorum on R.
///
/// Mirrors Go's `pipelinedMessageTimestamp`.
pub const PIPELINED_MESSAGE_TIMESTAMP: Duration = Duration::from_nanos(1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_display() {
        assert_eq!(format!("{}", EventType::None), "none");
        assert_eq!(format!("{}", EventType::VotePresent), "votePresent");
        assert_eq!(format!("{}", EventType::CertThreshold), "certThreshold");
        assert_eq!(
            format!("{}", EventType::CheckpointReached),
            "checkpointReached"
        );
    }

    #[test]
    fn event_type_default_is_none() {
        assert_eq!(EventType::default(), EventType::None);
    }

    #[test]
    fn serializable_error_display() {
        let err = SerializableError::new("test error");
        assert_eq!(format!("{err}"), "test error");
    }

    #[test]
    fn zero_event_none() {
        let e = zero_event(EventType::None);
        assert_eq!(e.event_type(), EventType::None);
    }

    #[test]
    fn zero_event_vote_present() {
        let e = zero_event(EventType::VotePresent);
        // The event_type is determined by the inner MessageEvent's t field,
        // which defaults to None. This matches Go's zeroEvent behavior.
        assert!(matches!(e, Event::Message(_)));
    }

    #[test]
    fn zero_event_threshold() {
        let e = zero_event(EventType::SoftThreshold);
        assert!(matches!(e, Event::Threshold(_)));
    }

    #[test]
    fn threshold_event_fresher_than_both_none() {
        let a = ThresholdEvent::default();
        let b = ThresholdEvent::default();
        assert!(a.fresher_than(&b));
    }

    #[test]
    fn threshold_event_fresher_than_self_none() {
        let a = ThresholdEvent::default();
        let b = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            ..ThresholdEvent::default()
        };
        assert!(!a.fresher_than(&b));
    }

    #[test]
    fn threshold_event_fresher_than_other_none() {
        let a = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            ..ThresholdEvent::default()
        };
        let b = ThresholdEvent::default();
        assert!(a.fresher_than(&b));
    }

    #[test]
    fn threshold_event_cert_is_freshest() {
        let a = ThresholdEvent {
            t: EventType::CertThreshold,
            round: Round(1),
            ..ThresholdEvent::default()
        };
        let b = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(10),
            ..ThresholdEvent::default()
        };
        assert!(a.fresher_than(&b));
        assert!(!b.fresher_than(&a));
    }

    #[test]
    fn threshold_event_next_fresher_than_soft_same_period() {
        let a = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(2),
            ..ThresholdEvent::default()
        };
        let b = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(2),
            ..ThresholdEvent::default()
        };
        assert!(a.fresher_than(&b));
    }

    #[test]
    fn threshold_event_later_period_fresher() {
        let a = ThresholdEvent {
            t: EventType::SoftThreshold,
            round: Round(1),
            period: Period(3),
            ..ThresholdEvent::default()
        };
        let b = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(2),
            ..ThresholdEvent::default()
        };
        assert!(a.fresher_than(&b));
    }

    #[test]
    fn threshold_event_next_bottom_fresher_than_next_value() {
        let a = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(2),
            proposal: BOTTOM,
            ..ThresholdEvent::default()
        };
        let b = ThresholdEvent {
            t: EventType::NextThreshold,
            round: Round(1),
            period: Period(2),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: algo_types::Address([0x01; 32]),
                block_digest: algo_types::Digest([0xaa; 32]),
                encoding_digest: algo_types::Digest([0xbb; 32]),
            },
            ..ThresholdEvent::default()
        };
        assert!(a.fresher_than(&b));
        assert!(!b.fresher_than(&a));
    }

    #[test]
    fn message_event_consensus_round() {
        let me = MessageEvent {
            t: EventType::VotePresent,
            input: {
                let mut input = InternalMessage::default();
                input.unauthenticated_vote.raw_vote.round = Round(42);
                input
            },
            ..MessageEvent::default()
        };
        assert_eq!(me.consensus_round(), Round(42));
    }

    #[test]
    fn event_display() {
        let e = Event::Empty(EmptyEvent);
        assert_eq!(format!("{e}"), "none");
    }
}
