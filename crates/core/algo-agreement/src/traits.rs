// Agreement protocol traits, matching go-algorand/agreement/abstractions.go.
//
// These traits define the interfaces that the agreement protocol depends on:
// - BlockValidator: validates incoming block proposals
// - ValidatedBlock: wraps a validated block
// - UnfinishedBlock: a block being assembled, needs final fields
// - BlockFactory: assembles block proposals
// - LedgerWriter: writes certified blocks to the ledger
// - AgreementLedger: full ledger interface (reader + writer)
// - RandomSource: random number generator for sortition timing

use algo_types::{Address, Block, Round};

use crate::certificate::Certificate;
use crate::ledger_reader::LedgerReader;
use crate::seed::Seed;

// ---------------------------------------------------------------------------
// AgreementError
// ---------------------------------------------------------------------------

/// Errors returned by agreement trait methods.
#[derive(Debug, Clone)]
pub enum AgreementError {
    /// The requested round is stale (already committed).
    ///
    /// Mirrors Go's `ErrAssembleBlockRoundStale`.
    RoundStale(Round),

    /// Block validation failed.
    ValidationFailed(String),

    /// Generic error with message.
    Other(String),
}

impl std::fmt::Display for AgreementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundStale(r) => {
                write!(f, "requested round {r} for AssembleBlock is stale")
            }
            Self::ValidationFailed(msg) => write!(f, "block validation failed: {msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AgreementError {}

// ---------------------------------------------------------------------------
// ValidatedBlock
// ---------------------------------------------------------------------------

/// A block that has been successfully validated and can be recorded in the ledger.
///
/// Mirrors Go's `agreement.ValidatedBlock` interface.
pub trait ValidatedBlock {
    /// Returns a reference to the underlying block that has been validated.
    fn block(&self) -> &Block;
}

// ---------------------------------------------------------------------------
// BlockValidator
// ---------------------------------------------------------------------------

/// Validates that a given Block may correctly be appended to the sequence
/// of entries agreed upon by the protocol so far.
///
/// Mirrors Go's `agreement.BlockValidator` interface.
///
/// The correctness of `validate` is essential to the correctness of the
/// protocol. A false positive may cause a fork; a false negative may cause
/// liveness loss.
pub trait BlockValidator {
    /// Validate the given block. Returns a `ValidatedBlock` on success.
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError>;
}

// ---------------------------------------------------------------------------
// UnfinishedBlock
// ---------------------------------------------------------------------------

/// A Block produced by a BlockFactory that must be finalized before being
/// proposed by agreement.
///
/// Mirrors Go's `agreement.UnfinishedBlock` interface.
pub trait UnfinishedBlock {
    /// Creates a proposable block by setting the cryptographically random seed
    /// and payout-related fields (proposer, eligible).
    ///
    /// After this call, the block's `Seed()` and `Digest()` must reflect
    /// the new seed value.
    fn finish_block(&self, seed: Seed, proposer: Address, eligible: bool) -> Block;

    /// Returns the round this unfinished block is for.
    fn round(&self) -> Round;
}

// ---------------------------------------------------------------------------
// BlockFactory
// ---------------------------------------------------------------------------

/// Assembles block proposals for a given round.
///
/// Mirrors Go's `agreement.BlockFactory` interface.
pub trait BlockFactory {
    /// Produces a new `UnfinishedBlock` for the given round.
    ///
    /// `addresses` is the list of participating addresses that may propose
    /// this block.
    ///
    /// Returns an error if the factory is unable to produce a block for the
    /// given round (e.g., `AgreementError::RoundStale`).
    fn assemble_block(
        &self,
        round: Round,
        addresses: &[Address],
    ) -> Result<Box<dyn UnfinishedBlock>, AgreementError>;
}

// ---------------------------------------------------------------------------
// LedgerWriter
// ---------------------------------------------------------------------------

/// Write access to the ledger — adds certified blocks.
///
/// Mirrors Go's `agreement.LedgerWriter` interface.
///
/// After any `ensure_*` method returns, subsequent `Seed`, `LookupAgreement`,
/// and `Circulation` calls on the `LedgerReader` must reflect the contents
/// of the written block.
pub trait LedgerWriter {
    /// Adds a block along with its authenticating certificate to the ledger.
    ///
    /// Does not wait until the block is written to disk; use
    /// `LedgerReader::wait_for_round` for that.
    fn ensure_block(&self, block: &Block, cert: &Certificate);

    /// Optimized version of `ensure_block` that works on a `ValidatedBlock`.
    fn ensure_validated_block(&self, vb: &dyn ValidatedBlock, cert: &Certificate);

    /// Signals the ledger to attempt to fetch a block matching the given
    /// certificate. Does not wait for the block to be written to disk;
    /// use `LedgerReader::wait_for_round` for that.
    ///
    /// Mirrors Go's `EnsureDigest(Certificate, *AsyncVoteVerifier)`.
    ///
    /// TODO: Add `&AsyncVoteVerifier` parameter once async vote verification
    /// is implemented (Go passes `*AsyncVoteVerifier` here).
    fn ensure_digest(&self, cert: &Certificate);
}

// ---------------------------------------------------------------------------
// AgreementLedger
// ---------------------------------------------------------------------------

/// Full ledger interface combining read and write access.
///
/// Mirrors Go's `agreement.Ledger` interface which composes `LedgerReader`
/// and `LedgerWriter`.
///
/// Must be safe for concurrent use.
pub trait AgreementLedger: LedgerReader + LedgerWriter {}

/// Blanket implementation: any type that implements both `LedgerReader` and
/// `LedgerWriter` automatically implements `AgreementLedger`.
impl<T: LedgerReader + LedgerWriter> AgreementLedger for T {}

// ---------------------------------------------------------------------------
// RandomSource
// ---------------------------------------------------------------------------

/// Random number generator abstraction used by the agreement protocol
/// to determine how long nodes wait on steps 5 and above.
///
/// Mirrors Go's `agreement.RandomSource` interface.
pub trait RandomSource {
    /// Returns a pseudo-random 64-bit value.
    fn uint64(&self) -> u64;
}

// ---------------------------------------------------------------------------
// MessageHandle / Message
// ---------------------------------------------------------------------------

/// An opaque handle referring to a specific network message.
///
/// Mirrors Go's `agreement.MessageHandle`. A value of `None` denotes
/// that the message is "sourceless".
pub type MessageHandle = Option<Box<dyn std::any::Any + Send + Sync>>;

/// A message encapsulating a handle and its payload.
///
/// Mirrors Go's `agreement.Message`.
#[derive(Debug)]
pub struct Message {
    /// An opaque handle identifying the source of this message.
    pub handle: MessageHandle,
    /// The payload bytes.
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Protocol Tag
// ---------------------------------------------------------------------------

/// A protocol message tag, used to multiplex agreement messages on the network.
///
/// Mirrors Go's `protocol.Tag` (a string alias).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag(pub &'static str);

/// The tag for agreement vote messages (`"AV"`).
pub const AGREEMENT_VOTE_TAG: &str = "AV";

/// The tag for proposal payload messages (`"PP"`).
pub const PROPOSAL_PAYLOAD_TAG: &str = "PP";

/// The tag for vote bundle messages (`"VB"`).
pub const VOTE_BUNDLE_TAG: &str = "VB";

// ---------------------------------------------------------------------------
// AgreementNetwork
// ---------------------------------------------------------------------------

/// Network abstraction used by the agreement protocol.
///
/// Mirrors Go's `agreement.Network` interface.
pub trait AgreementNetwork {
    /// Returns a receiver for messages with the given protocol tag.
    ///
    /// This is a single-call-per-tag API: calling it again for the same tag
    /// creates a new channel, and any messages buffered in the previous
    /// receiver are lost. This is an intentional constraint matching Go's
    /// channel semantics where `Messages()` returns a moved `<-chan`.
    ///
    /// Mirrors Go's `Messages(protocol.Tag) <-chan Message`.
    fn messages(&self, tag: &Tag) -> std::sync::mpsc::Receiver<Message>;

    /// Broadcast a message with the given tag to all neighbors.
    ///
    /// Best-effort, ordered delivery. Returns an error if the broadcast fails.
    ///
    /// Mirrors Go's `Broadcast(protocol.Tag, []byte) error`.
    fn broadcast(&self, tag: &Tag, data: &[u8]) -> Result<(), AgreementError>;

    /// Relay a message to all neighbors except the one identified by `handle`.
    ///
    /// Passing `None` as the handle is equivalent to calling `broadcast`.
    ///
    /// Mirrors Go's `Relay(MessageHandle, protocol.Tag, []byte) error`.
    fn relay(&self, handle: &MessageHandle, tag: &Tag, data: &[u8]) -> Result<(), AgreementError>;

    /// Hint to the network to disconnect from the peer identified by `handle`.
    ///
    /// Mirrors Go's `Disconnect(MessageHandle)`.
    fn disconnect(&self, handle: &MessageHandle);

    /// Notify the network that the agreement service is ready to receive.
    ///
    /// Mirrors Go's `Start()`.
    fn start(&self);
}

// ---------------------------------------------------------------------------
// AgreementKeyManager
// ---------------------------------------------------------------------------

/// Key management abstraction used by the agreement protocol.
///
/// Mirrors Go's `agreement.KeyManager` interface.
///
/// This is defined locally rather than re-exporting from `algo-ledger` because
/// `algo-agreement` does not depend on `algo-ledger`. The ledger crate's
/// `KeyManager` trait may be adapted to implement this trait.
pub trait AgreementKeyManager {
    /// Returns voting keys valid for `voting_round` that were available at
    /// `keys_round`.
    ///
    /// Mirrors Go's `VotingKeys(votingRound, keysRound basics.Round)`.
    fn voting_keys(&self, voting_round: Round, keys_round: Round) -> Vec<ParticipationRecord>;

    /// Record that a participation action has been taken.
    ///
    /// This should be asynchronous to avoid impacting agreement.
    ///
    /// Mirrors Go's `Record(account, round, participationType)`.
    fn record(&self, account: &Address, round: Round, action: ParticipationAction);
}

/// A participation record for a specific round, containing the address
/// and key material needed for voting.
///
/// Mirrors Go's `account.ParticipationRecordForRound`.
#[derive(Debug, Clone)]
pub struct ParticipationRecord {
    /// The participating account address.
    pub address: Address,
    /// The OTS master public key (32 bytes).
    pub vote_id: [u8; 32],
    /// The VRF selection public key (32 bytes).
    pub selection_id: [u8; 32],
    /// First round this key is valid.
    pub vote_first_valid: Round,
    /// Last round this key is valid.
    pub vote_last_valid: Round,
    /// Key dilution parameter.
    pub vote_key_dilution: u64,
}

/// An action recorded by the key manager when participation occurs.
///
/// Mirrors Go's `account.ParticipationAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationAction {
    /// The account proposed a block.
    Proposed,
    /// The account voted in agreement.
    Voted,
    /// The account participated in a state proof.
    StateProof,
}

// ---------------------------------------------------------------------------
// EventsProcessingMonitor
// ---------------------------------------------------------------------------

/// An abstraction over the inner queues of the agreement service.
///
/// Allows an external client to monitor the activity of the various event
/// queues.
///
/// Mirrors Go's `agreement.EventsProcessingMonitor` interface.
pub trait EventsProcessingMonitor {
    /// Called when the length of a named event queue changes.
    ///
    /// Mirrors Go's `UpdateEventsQueue(queueName string, queueLength int)`.
    fn update_events_queue(&self, queue_name: &str, queue_length: usize);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agreement_error_display() {
        let err = AgreementError::RoundStale(Round(42));
        assert_eq!(
            format!("{err}"),
            "requested round 42 for AssembleBlock is stale"
        );

        let err = AgreementError::ValidationFailed("bad block".to_string());
        assert_eq!(format!("{err}"), "block validation failed: bad block");

        let err = AgreementError::Other("something went wrong".to_string());
        assert_eq!(format!("{err}"), "something went wrong");
    }

    #[test]
    fn agreement_error_is_error() {
        let err: Box<dyn std::error::Error> = Box::new(AgreementError::RoundStale(Round(1)));
        assert!(!err.to_string().is_empty());
    }

    /// Verify that `AgreementLedger` blanket impl works by checking trait bounds.
    #[test]
    fn agreement_ledger_trait_bounds() {
        fn _assert_agreement_ledger<T: AgreementLedger>() {}
        // This is a compile-time check — if it compiles, the blanket impl works.
    }
}
