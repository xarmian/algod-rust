// Action types for the agreement protocol state machine.
//
// Mirrors go-algorand/agreement/actions.go.
//
// Every action type from the Go implementation is represented here. The Go
// `action` interface is modeled as the `Action` enum, with each variant
// wrapping the corresponding action struct.

use std::fmt;
use std::time::Duration;

use algo_types::Round;

use crate::certificate::Certificate;
use crate::events::{CompoundMessage, InternalMessage, MessageEvent, Proposal, SerializableError};
use crate::step::{Period, Step};
use crate::vote::{ProposalValue, UnauthenticatedVote, BOTTOM};

// ---------------------------------------------------------------------------
// ActionType
// ---------------------------------------------------------------------------

/// Identifies the particular type of action to be performed.
///
/// Mirrors Go's `actionType` enum in agreement/actions.go.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActionType {
    /// No-op action.
    #[default]
    Noop = 0,

    // -- Network actions -----------------------------------------------------
    /// Ignore a message.
    Ignore,
    /// Broadcast a message to all peers.
    Broadcast,
    /// Relay a message (broadcast minus sender).
    Relay,
    /// Disconnect from a peer.
    Disconnect,
    /// Broadcast multiple votes.
    BroadcastVotes,

    // -- Crypto actions ------------------------------------------------------
    /// Verify a vote.
    VerifyVote,
    /// Verify a payload.
    VerifyPayload,
    /// Verify a bundle.
    VerifyBundle,

    // -- Ledger actions ------------------------------------------------------
    /// Ensure a block is written to the ledger.
    Ensure,
    /// Stage a digest for a block.
    StageDigest,

    // -- Time actions --------------------------------------------------------
    /// Reset the clock to zero.
    Rezero,

    // -- Logical actions -----------------------------------------------------
    /// Attest (vote) for a proposal.
    Attest,
    /// Assemble a new block proposal.
    Assemble,
    /// Repropose an existing proposal for a new period.
    Repropose,

    // -- Disk actions --------------------------------------------------------
    /// Checkpoint state to disk.
    Checkpoint,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Noop => "noop",
            Self::Ignore => "ignore",
            Self::Broadcast => "broadcast",
            Self::Relay => "relay",
            Self::Disconnect => "disconnect",
            Self::BroadcastVotes => "broadcastVotes",
            Self::VerifyVote => "verifyVote",
            Self::VerifyPayload => "verifyPayload",
            Self::VerifyBundle => "verifyBundle",
            Self::Ensure => "ensure",
            Self::StageDigest => "stageDigest",
            Self::Rezero => "rezero",
            Self::Attest => "attest",
            Self::Assemble => "assemble",
            Self::Repropose => "repropose",
            Self::Checkpoint => "checkpoint",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Action structs
// ---------------------------------------------------------------------------

/// A no-op action. Does nothing.
///
/// Mirrors Go's `noopAction`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoopAction;

impl fmt::Display for NoopAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ActionType::Noop)
    }
}

/// A network action: ignore, broadcast, broadcastVotes, relay, or disconnect.
///
/// Mirrors Go's `networkAction`.
#[derive(Debug, Clone)]
pub struct NetworkAction {
    /// The specific action type.
    pub t: ActionType,
    /// The protocol tag for the message.
    pub tag: String,

    /// Unauthenticated vote (for AgreementVoteTag).
    pub unauthenticated_vote: UnauthenticatedVote,
    /// Unauthenticated bundle (for VoteBundleTag).
    pub unauthenticated_bundle: crate::bundle::UnauthenticatedBundle,
    /// Compound message (for ProposalPayloadTag).
    pub compound_message: CompoundMessage,

    /// Multiple unauthenticated votes (for BroadcastVotes).
    pub unauthenticated_votes: Vec<UnauthenticatedVote>,

    /// Error reason (for Ignore/Disconnect).
    pub err: Option<SerializableError>,
}

impl Default for NetworkAction {
    fn default() -> Self {
        Self {
            t: ActionType::Noop,
            tag: String::new(),
            unauthenticated_vote: UnauthenticatedVote::default(),
            unauthenticated_bundle: crate::bundle::UnauthenticatedBundle::default(),
            compound_message: CompoundMessage::default(),
            unauthenticated_votes: Vec::new(),
            err: None,
        }
    }
}

impl fmt::Display for NetworkAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.t == ActionType::Ignore || self.t == ActionType::Disconnect {
            write!(f, "{}: {:?}", self.t, self.err)
        } else {
            write!(f, "{}: {}", self.t, self.tag)
        }
    }
}

/// A crypto action: verifyVote, verifyPayload, or verifyBundle.
///
/// Mirrors Go's `cryptoAction`.
#[derive(Debug, Clone)]
pub struct CryptoAction {
    /// The specific action type.
    pub t: ActionType,
    /// The message to verify.
    pub m: InternalMessage,
    /// Proposal value (for context).
    pub proposal: ProposalValue,
    /// Round for verification.
    pub round: Round,
    /// Period for verification.
    pub period: Period,
    /// Step for verification.
    pub step: Step,
    /// Whether this is a pinned payload.
    pub pinned: bool,
    /// Task index for tracking.
    pub task_index: u64,
}

impl Default for CryptoAction {
    fn default() -> Self {
        Self {
            t: ActionType::Noop,
            m: InternalMessage::default(),
            proposal: BOTTOM,
            round: Round(0),
            period: Period(0),
            step: Step(0),
            pinned: false,
            task_index: 0,
        }
    }
}

impl fmt::Display for CryptoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.t {
            ActionType::VerifyVote => {
                write!(
                    f,
                    "{}: {}-{} TaskIndex {}",
                    self.t, self.round, self.period, self.task_index
                )
            }
            ActionType::VerifyPayload => {
                write!(
                    f,
                    "{}: {}-{} Pinned {}",
                    self.t, self.round, self.period, self.pinned
                )
            }
            ActionType::VerifyBundle => {
                write!(
                    f,
                    "{}: {}-{}-{}",
                    self.t, self.round, self.period, self.step
                )
            }
            _ => write!(f, "{}", self.t),
        }
    }
}

/// An ensure action: write a block and certificate to the ledger.
///
/// Mirrors Go's `ensureAction`.
#[derive(Debug, Clone)]
pub struct EnsureAction {
    /// The proposal payload to give to the ledger.
    pub payload: Proposal,
    /// The certificate proving commitment.
    pub certificate: Certificate,
    /// The time that the lowest proposal-vote was validated for
    /// `credentialRoundLag` rounds ago.
    pub vote_validated_at: Duration,
    /// The dynamic filter timeout calculated for this round (for telemetry).
    pub dynamic_filter_timeout: Duration,
}

impl fmt::Display for EnsureAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?}: {}, {}, {:?}",
            ActionType::Ensure,
            self.payload.unauthenticated_proposal.block_digest(),
            self.certificate.round,
            self.certificate.period,
            self.certificate.proposal.block_digest,
        )
    }
}

/// A stage-digest action: signal the ledger to fetch a block for a certificate.
///
/// Mirrors Go's `stageDigestAction`.
#[derive(Debug, Clone)]
pub struct StageDigestAction {
    /// The certificate identifying the block.
    pub certificate: Certificate,
}

impl fmt::Display for StageDigestAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?}. {}. {}",
            ActionType::StageDigest,
            self.certificate.proposal.block_digest,
            self.certificate.round,
            self.certificate.period,
        )
    }
}

/// A rezero action: reset the clock to zero.
///
/// Mirrors Go's `rezeroAction`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RezeroAction {
    /// The round that is starting.
    pub round: Round,
}

impl fmt::Display for RezeroAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ActionType::Rezero)
    }
}

/// A pseudonode action: assemble, repropose, or attest.
///
/// Mirrors Go's `pseudonodeAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudonodeAction {
    /// The specific action type: Assemble, Repropose, or Attest.
    pub t: ActionType,
    /// The round.
    pub round: Round,
    /// The period.
    pub period: Period,
    /// The step (relevant for Attest).
    pub step: Step,
    /// The proposal value (relevant for Repropose/Attest).
    pub proposal: ProposalValue,
}

impl Default for PseudonodeAction {
    fn default() -> Self {
        Self {
            t: ActionType::Noop,
            round: Round(0),
            period: Period(0),
            step: Step(0),
            proposal: BOTTOM,
        }
    }
}

impl PseudonodeAction {
    /// Returns whether this action is persistent (must survive restarts).
    ///
    /// Only `Attest` actions are persistent.
    pub fn persistent(&self) -> bool {
        self.t == ActionType::Attest
    }
}

impl fmt::Display for PseudonodeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}-{}-{}: {:?}",
            self.t, self.round, self.period, self.step, self.proposal.block_digest,
        )
    }
}

/// A checkpoint action: persist agreement state to disk.
///
/// Mirrors Go's `checkpointAction`.
#[derive(Debug, Clone, Default)]
pub struct CheckpointAction {
    /// Round at the checkpoint.
    pub round: Round,
    /// Period at the checkpoint.
    pub period: Period,
    /// Step at the checkpoint.
    pub step: Step,
    /// Error from persisting state (if any).
    pub err: Option<SerializableError>,
}

impl fmt::Display for CheckpointAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ActionType::Checkpoint)
    }
}

// ---------------------------------------------------------------------------
// Action (top-level enum)
// ---------------------------------------------------------------------------

/// The top-level action enum wrapping all action types.
///
/// This models Go's `action` interface with its `t() actionType` method.
#[derive(Debug, Clone)]
pub enum Action {
    /// No-op.
    Noop(NoopAction),
    /// Network action (ignore, broadcast, relay, disconnect, broadcastVotes).
    Network(Box<NetworkAction>),
    /// Crypto action (verifyVote, verifyPayload, verifyBundle).
    Crypto(Box<CryptoAction>),
    /// Ensure action (write block to ledger).
    Ensure(Box<EnsureAction>),
    /// Stage-digest action (signal ledger to fetch a block).
    StageDigest(Box<StageDigestAction>),
    /// Rezero action (reset clock).
    Rezero(RezeroAction),
    /// Pseudonode action (assemble, repropose, attest).
    Pseudonode(PseudonodeAction),
    /// Checkpoint action (persist state to disk).
    Checkpoint(CheckpointAction),
}

impl Action {
    /// Returns the `ActionType` for this action.
    ///
    /// Mirrors Go's `action.t()`.
    pub fn action_type(&self) -> ActionType {
        match self {
            Self::Noop(_) => ActionType::Noop,
            Self::Network(ref a) => a.t,
            Self::Crypto(ref a) => a.t,
            Self::Ensure(_) => ActionType::Ensure,
            Self::StageDigest(_) => ActionType::StageDigest,
            Self::Rezero(_) => ActionType::Rezero,
            Self::Pseudonode(ref a) => a.t,
            Self::Checkpoint(_) => ActionType::Checkpoint,
        }
    }

    /// Returns whether this action is persistent (must survive restarts).
    ///
    /// Mirrors Go's `action.persistent()`.
    pub fn persistent(&self) -> bool {
        match self {
            Self::Pseudonode(ref a) => a.persistent(),
            _ => false,
        }
    }
}

impl Default for Action {
    fn default() -> Self {
        Self::Noop(NoopAction)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Noop(ref a) => write!(f, "{a}"),
            Self::Network(ref a) => write!(f, "{a}"),
            Self::Crypto(ref a) => write!(f, "{a}"),
            Self::Ensure(ref a) => write!(f, "{a}"),
            Self::StageDigest(ref a) => write!(f, "{a}"),
            Self::Rezero(ref a) => write!(f, "{a}"),
            Self::Pseudonode(ref a) => write!(f, "{a}"),
            Self::Checkpoint(ref a) => write!(f, "{a}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors (matching Go free functions)
// ---------------------------------------------------------------------------

/// Creates an ignore action for the given message event and error reason.
///
/// Mirrors Go's `ignoreAction`.
pub fn ignore_action(err: SerializableError) -> Action {
    Action::Network(Box::new(NetworkAction {
        t: ActionType::Ignore,
        err: Some(err),
        ..NetworkAction::default()
    }))
}

/// Creates a disconnect action for the given message event and error reason.
///
/// Mirrors Go's `disconnectAction`.
pub fn disconnect_action(err: SerializableError) -> Action {
    Action::Network(Box::new(NetworkAction {
        t: ActionType::Disconnect,
        err: Some(err),
        ..NetworkAction::default()
    }))
}

/// Creates a verify-vote crypto action.
///
/// Mirrors Go's `verifyVoteAction`.
pub fn verify_vote_action(e: &MessageEvent, r: Round, p: Period, task_index: u64) -> Action {
    Action::Crypto(Box::new(CryptoAction {
        t: ActionType::VerifyVote,
        m: e.input.clone(),
        round: r,
        period: p,
        task_index,
        ..CryptoAction::default()
    }))
}

/// Creates a verify-payload crypto action.
///
/// Mirrors Go's `verifyPayloadAction`.
pub fn verify_payload_action(e: &MessageEvent, r: Round, p: Period, pinned: bool) -> Action {
    Action::Crypto(Box::new(CryptoAction {
        t: ActionType::VerifyPayload,
        m: e.input.clone(),
        round: r,
        period: p,
        pinned,
        ..CryptoAction::default()
    }))
}

/// Creates a verify-bundle crypto action.
///
/// Mirrors Go's `verifyBundleAction`.
pub fn verify_bundle_action(e: &MessageEvent, r: Round, p: Period, s: Step) -> Action {
    Action::Crypto(Box::new(CryptoAction {
        t: ActionType::VerifyBundle,
        m: e.input.clone(),
        round: r,
        period: p,
        step: s,
        ..CryptoAction::default()
    }))
}

/// Creates a zeroed action of a given type.
///
/// Mirrors Go's `zeroAction`.
pub fn zero_action(t: ActionType) -> Action {
    match t {
        ActionType::Noop => Action::Noop(NoopAction),
        ActionType::Ignore
        | ActionType::Broadcast
        | ActionType::Relay
        | ActionType::Disconnect
        | ActionType::BroadcastVotes => Action::Network(Box::default()),
        ActionType::VerifyVote | ActionType::VerifyPayload | ActionType::VerifyBundle => {
            Action::Crypto(Box::default())
        }
        ActionType::Ensure => Action::Ensure(Box::new(EnsureAction {
            payload: Proposal::default(),
            certificate: Certificate::default(),
            vote_validated_at: Duration::ZERO,
            dynamic_filter_timeout: Duration::ZERO,
        })),
        ActionType::StageDigest => Action::StageDigest(Box::new(StageDigestAction {
            certificate: Certificate::default(),
        })),
        ActionType::Rezero => Action::Rezero(RezeroAction::default()),
        ActionType::Attest | ActionType::Assemble | ActionType::Repropose => {
            Action::Pseudonode(PseudonodeAction::default())
        }
        ActionType::Checkpoint => Action::Checkpoint(CheckpointAction::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_type_display() {
        assert_eq!(format!("{}", ActionType::Noop), "noop");
        assert_eq!(format!("{}", ActionType::Broadcast), "broadcast");
        assert_eq!(format!("{}", ActionType::VerifyVote), "verifyVote");
        assert_eq!(format!("{}", ActionType::Ensure), "ensure");
        assert_eq!(format!("{}", ActionType::Checkpoint), "checkpoint");
    }

    #[test]
    fn action_type_default_is_noop() {
        assert_eq!(ActionType::default(), ActionType::Noop);
    }

    #[test]
    fn noop_action_not_persistent() {
        let a = Action::Noop(NoopAction);
        assert!(!a.persistent());
    }

    #[test]
    fn pseudonode_attest_is_persistent() {
        let a = Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            ..PseudonodeAction::default()
        });
        assert!(a.persistent());
    }

    #[test]
    fn pseudonode_assemble_not_persistent() {
        let a = Action::Pseudonode(PseudonodeAction {
            t: ActionType::Assemble,
            ..PseudonodeAction::default()
        });
        assert!(!a.persistent());
    }

    #[test]
    fn zero_action_noop() {
        let a = zero_action(ActionType::Noop);
        assert_eq!(a.action_type(), ActionType::Noop);
    }

    #[test]
    fn zero_action_network() {
        let a = zero_action(ActionType::Broadcast);
        assert!(matches!(a, Action::Network(_)));
    }

    #[test]
    fn zero_action_crypto() {
        let a = zero_action(ActionType::VerifyVote);
        assert!(matches!(a, Action::Crypto(_)));
    }

    #[test]
    fn zero_action_ensure() {
        let a = zero_action(ActionType::Ensure);
        assert_eq!(a.action_type(), ActionType::Ensure);
    }

    #[test]
    fn zero_action_pseudonode() {
        let a = zero_action(ActionType::Attest);
        assert!(matches!(a, Action::Pseudonode(_)));
    }

    #[test]
    fn ignore_action_constructor() {
        let a = ignore_action(SerializableError::new("test"));
        assert_eq!(a.action_type(), ActionType::Ignore);
    }

    #[test]
    fn disconnect_action_constructor() {
        let a = disconnect_action(SerializableError::new("bad peer"));
        assert_eq!(a.action_type(), ActionType::Disconnect);
    }

    #[test]
    fn action_display() {
        let a = Action::Noop(NoopAction);
        assert_eq!(format!("{a}"), "noop");

        let a = Action::Rezero(RezeroAction { round: Round(5) });
        assert_eq!(format!("{a}"), "rezero");
    }
}
