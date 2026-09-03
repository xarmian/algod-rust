// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// - CryptoVerifier: async cryptographic verification of votes, proposals, bundles

use algo_types::{Address, Block, Round};

use crate::certificate::Certificate;
use crate::events::{InternalMessage, SerializableError};
use crate::ledger_reader::LedgerReader;
use crate::seed::Seed;
use crate::step::Period;
use crate::vote::Vote;

// ---------------------------------------------------------------------------
// AsyncVoteVerifier
// ---------------------------------------------------------------------------

/// A handle to the asynchronous vote verification machinery.
///
/// Mirrors Go's `agreement.AsyncVoteVerifier` — a worker pool that verifies
/// agreement votes in the background.  The `EnsureDigest` method on
/// `LedgerWriter` passes a reference to this verifier so the catchup service
/// can authenticate certificates for blocks it fetches.
///
/// The current implementation is a lightweight placeholder: the real
/// verification logic is handled by `CryptoVerifier` / `AsyncCryptoVerifier`.
/// This struct exists to give `PendingUnmatchedCertificate` an owned reference
/// that can travel across threads to the catchup service.
#[derive(Debug, Clone)]
pub struct AsyncVoteVerifier {
    // Intentionally empty for now.
    // The Go struct wraps an exec pool, done channel, context, etc.
    // These will be added when the catchup service needs real verification.
    _private: (),
}

impl AsyncVoteVerifier {
    /// Create a new `AsyncVoteVerifier`.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Shut down the verifier and wait for all workers to finish.
    ///
    /// Mirrors Go's `AsyncVoteVerifier.Quit()`.
    pub fn quit(&self) {
        // No background workers to shut down yet.
    }
}

impl Default for AsyncVoteVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PendingUnmatchedCertificate
// ---------------------------------------------------------------------------

/// A certificate paired with a vote verifier, queued for the catchup service.
///
/// Mirrors Go's `catchup.PendingUnmatchedCertificate`.  When the agreement
/// service calls `EnsureDigest`, it packages the certificate and vote verifier
/// into this struct and sends it on a channel to the catchup service, which
/// will fetch the matching block and authenticate it.
#[derive(Debug, Clone)]
pub struct PendingUnmatchedCertificate {
    /// The certificate identifying the block to fetch.
    pub cert: Certificate,
    /// The vote verifier for authenticating the fetched block's certificate.
    pub vote_verifier: AsyncVoteVerifier,
}

// ---------------------------------------------------------------------------
// NetworkAdvancer
// ---------------------------------------------------------------------------

/// Trait for signaling network progress.
///
/// Mirrors the `OnNetworkAdvance()` method on Go's `network.GossipNode`.
/// The agreement service calls this when it makes progress (e.g., a block is
/// committed or a certificate is received) so the network layer can perform
/// mesh maintenance, refresh peer connections, etc.
///
/// This trait decouples `algo-agreement` and `algo-ledger` from the network
/// crate.  Concrete implementations wrap a `GossipNode` or similar.
pub trait NetworkAdvancer: Send + Sync {
    /// Notify the network that the agreement protocol made progress.
    fn on_network_advance(&self);
}

/// A no-op `NetworkAdvancer` for tests and stubs.
#[derive(Debug, Clone, Default)]
pub struct NoOpNetworkAdvancer;

impl NetworkAdvancer for NoOpNetworkAdvancer {
    fn on_network_advance(&self) {
        // No-op.
    }
}

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
pub trait ValidatedBlock: Send + Sync {
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
pub trait BlockValidator: Send + Sync {
    /// Validate the given block. Returns a `ValidatedBlock` on success.
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError>;

    /// Update the previous block timestamp after a block is committed.
    ///
    /// Default is a no-op. Concrete implementations (e.g., `BlockValidatorBridge`)
    /// override this to track the latest committed timestamp for subsequent
    /// validation.
    fn set_prev_timestamp(&self, _ts: i64) {}
}

/// Blanket implementation: `Arc<T>` delegates to the inner `T`.
///
/// This allows a single `Arc<BlockValidatorBridge>` to be shared between
/// `Parameters` (which takes `BV: BlockValidator` by value) and
/// `AsyncCryptoVerifier` (which takes `Arc<BV>`), ensuring both see the
/// same mutable state (e.g., `prev_timestamp`).
impl<T: BlockValidator> BlockValidator for std::sync::Arc<T> {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        (**self).validate(block)
    }

    fn set_prev_timestamp(&self, ts: i64) {
        (**self).set_prev_timestamp(ts);
    }
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
    fn ensure_digest(&self, cert: &Certificate, verifier: &AsyncVoteVerifier);
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
/// Mirrors Go's `agreement.MessageHandle` (an `interface{}` that travels
/// alongside the message through the demux + crypto pipeline so the
/// player can later relay or disconnect the originating peer). A value
/// of `None` denotes that the message is "sourceless" — i.e. the player
/// itself produced the payload, in which case the player's
/// `relay-as-proposer` branch fires.
///
/// Backed by `Arc` (not `Box`) so cloning preserves the handle: the
/// crypto verifier path clones the message into its action and back into
/// the response event; if cloning dropped the handle, network-origin
/// payloads would be misclassified as locally-produced and the player
/// would emit the proposer-relay action redundantly. Several internal
/// types (`InternalMessage`, `NetworkAction`) hold this field via a
/// custom `Clone` impl that previously zeroed it; those impls now
/// `Arc::clone` instead.
pub type MessageHandle = Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>;

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
    fn messages(&self, tag: &Tag) -> crossbeam_channel::Receiver<Message>;

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

    /// Load the signing secrets (VRF + OTS) for `account`'s participation key
    /// valid at `voting_round` (selected using `keys_round`'s online state), if
    /// this key manager has them.
    ///
    /// The pseudonode calls this each round it loads voting keys, so the secrets
    /// track the public records across participation-key validity-window
    /// boundaries (a key that becomes effective later, or a mid-run rotation) —
    /// which a one-time statically-registered map cannot. Mirrors go's account
    /// manager handing per-round `account.Participation` secrets to agreement.
    ///
    /// The default returns `None`; the pseudonode then falls back to any keys
    /// registered via `register_signing_keys`. Implementations backed by a
    /// participation store (e.g. the node's key-manager bridge) override this.
    fn signing_keys_for(
        &self,
        _account: &Address,
        _voting_round: Round,
        _keys_round: Round,
    ) -> Option<crate::pseudonode::AccountSigningKeys> {
        None
    }
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
// CryptoVerifier
// ---------------------------------------------------------------------------

/// Result of asynchronous vote verification.
///
/// Mirrors Go's `asyncVerifyVoteResponse` in agreement/asyncVoteVerifier.go.
#[derive(Debug)]
pub struct CryptoVoteVerifyResult {
    /// The verified vote (set on success).
    pub vote: Option<Vote>,
    /// The internal message associated with the verification request.
    pub message: InternalMessage,
    /// Task index for tracking through the pipeline.
    pub task_index: u64,
    /// Error from verification (set on failure).
    pub err: Option<SerializableError>,
    /// Whether the request was cancelled before verification completed.
    pub cancelled: bool,
}

/// Result of asynchronous proposal or bundle verification.
///
/// Mirrors Go's `cryptoResult` in agreement/cryptoVerifier.go.
#[derive(Debug)]
pub struct CryptoResult {
    /// The internal message associated with the verification request.
    pub message: InternalMessage,
    /// Task index for tracking through the pipeline.
    pub task_index: u64,
    /// Error from verification (set on failure).
    pub err: Option<SerializableError>,
    /// Whether the request was cancelled before verification completed.
    pub cancelled: bool,
}

/// Request to verify a vote asynchronously.
///
/// Mirrors Go's `cryptoVoteRequest`.
#[derive(Debug)]
pub struct CryptoVoteRequest {
    /// The message containing the vote to verify.
    pub message: InternalMessage,
    /// Caller-specific index, passed back in the response.
    pub task_index: u64,
    /// The round to verify against.
    pub round: Round,
    /// The period associated with the message.
    pub period: Period,
}

/// Request to verify a proposal asynchronously.
///
/// Mirrors Go's `cryptoProposalRequest`.
#[derive(Debug)]
pub struct CryptoProposalRequest {
    /// The message containing the proposal to verify.
    pub message: InternalMessage,
    /// Caller-specific index, passed back in the response.
    pub task_index: u64,
    /// The round to verify against.
    pub round: Round,
    /// The period associated with the message.
    pub period: Period,
    /// Whether this is a pinned value for the given round.
    pub pinned: bool,
}

/// Request to verify a bundle asynchronously.
///
/// Mirrors Go's `cryptoBundleRequest`.
#[derive(Debug)]
pub struct CryptoBundleRequest {
    /// The message containing the bundle to verify.
    pub message: InternalMessage,
    /// Caller-specific index, passed back in the response.
    pub task_index: u64,
    /// The round to verify against.
    pub round: Round,
    /// The period associated with the message.
    pub period: Period,
    /// Whether this is a cert bundle.
    pub certify: bool,
}

/// Asynchronous cryptographic verifier for agreement messages.
///
/// Mirrors Go's `cryptoVerifier` interface in agreement/cryptoVerifier.go.
///
/// Callers submit verification requests via `verify_vote`, `verify_proposal`,
/// and `verify_bundle`, and obtain results by receiving from the channels
/// returned by `verified_votes` and `verified`.
pub trait CryptoVerifier: Send + 'static {
    /// Enqueue a vote for asynchronous verification.
    ///
    /// Mirrors Go's `VerifyVote(ctx, cryptoVoteRequest)`.
    fn verify_vote(&self, request: CryptoVoteRequest);

    /// Enqueue a proposal for asynchronous verification.
    ///
    /// Mirrors Go's `VerifyProposal(ctx, cryptoProposalRequest)`.
    fn verify_proposal(&self, request: CryptoProposalRequest);

    /// Enqueue a bundle for asynchronous verification.
    ///
    /// Mirrors Go's `VerifyBundle(ctx, cryptoBundleRequest)`.
    fn verify_bundle(&self, request: CryptoBundleRequest);

    /// Returns a receiver for verified vote results.
    ///
    /// Mirrors Go's `VerifiedVotes() <-chan asyncVerifyVoteResponse`.
    fn verified_votes(&self) -> &crossbeam_channel::Receiver<CryptoVoteVerifyResult>;

    /// Returns a receiver for verified proposal/bundle results for the given tag.
    ///
    /// - If `tag == "PP"` (ProposalPayloadTag): returns proposal verification results.
    /// - If `tag == "VB"` (VoteBundleTag): returns bundle verification results.
    ///
    /// Mirrors Go's `Verified(tag protocol.Tag) <-chan cryptoResult`.
    fn verified(&self, tag: &str) -> &crossbeam_channel::Receiver<CryptoResult>;

    /// Returns whether the input channel for the given tag is full.
    ///
    /// The demux uses this to apply backpressure and avoid deadlocks.
    ///
    /// Mirrors Go's `ChannelFull(tag protocol.Tag) bool`.
    fn channel_full(&self, tag: &str) -> bool;

    /// Shut down the verifier worker threads.
    ///
    /// Mirrors Go's `Quit()`.
    fn quit(&self);
}

/// Blanket impl so an `Arc<C>` can be used anywhere a `C: CryptoVerifier` is
/// expected (e.g. as `Parameters::crypto`), while a second `Arc` clone stays
/// with the caller for out-of-band inspection (queue lengths, etc.) — no go
/// equivalent needed, since go's `cryptoVerifier` is always used through a
/// pointer already. Added for issue #920: the multi-node test harness
/// (`crates/core/algo-agreement/tests/simulate/`) needs a live handle to
/// each node's verifier to fold its output-channel backlog into
/// `ActivityMonitor::wait_for_quiet`'s quiescence check (previously stubbed
/// to `|| 0`, unable to detect a verified-but-not-yet-drained proposal or
/// vote sitting in the verifier's output channel between polls).
impl<C: CryptoVerifier + Send + Sync + ?Sized> CryptoVerifier for std::sync::Arc<C> {
    fn verify_vote(&self, request: CryptoVoteRequest) {
        (**self).verify_vote(request)
    }

    fn verify_proposal(&self, request: CryptoProposalRequest) {
        (**self).verify_proposal(request)
    }

    fn verify_bundle(&self, request: CryptoBundleRequest) {
        (**self).verify_bundle(request)
    }

    fn verified_votes(&self) -> &crossbeam_channel::Receiver<CryptoVoteVerifyResult> {
        (**self).verified_votes()
    }

    fn verified(&self, tag: &str) -> &crossbeam_channel::Receiver<CryptoResult> {
        (**self).verified(tag)
    }

    fn channel_full(&self, tag: &str) -> bool {
        (**self).channel_full(tag)
    }

    fn quit(&self) {
        (**self).quit()
    }
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
