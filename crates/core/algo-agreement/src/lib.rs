// algo-agreement: Algorand agreement protocol types and helpers.
//
// Mirrors go-algorand/agreement (types, step/period, committee sizing)
// and go-algorand/data/committee (Selector, Seed, BalanceRecord).

pub mod actions;
mod bundle;
mod certificate;
mod credential;
pub mod demux;
pub mod events;
#[cfg(test)]
mod golden_vectors;
mod hashable;
mod ledger_reader;
mod lookback;
pub mod player;
mod proposal;
pub mod proposal_manager;
pub mod proposal_store;
pub mod proposal_tracker;
pub mod pseudonode;
pub mod router;
mod seed;
mod selector;
mod step;
pub mod stubs;
pub mod traits;
pub mod types;
mod vote;
pub mod vote_aggregator;
pub mod vote_auxiliary;
pub mod vote_tracker;

pub use bundle::{
    Bundle, BundleError, EquivocationVoteAuthenticator, UnauthenticatedBundle, VoteAuthenticator,
};
pub use certificate::{Certificate, CertificateError};
pub use credential::{
    Credential, CredentialError, HashableCredential, Membership, UnauthenticatedCredential,
};
pub use hashable::{hash_obj, hash_rep, Hashable};

/// Size of a VRF proof in bytes.
pub const VRF_PROOF_SIZE: usize = 80;
pub use ledger_reader::{
    membership_from_ledger, BalanceRecord, LedgerError, LedgerReader, OnlineAccountData,
};
pub use lookback::{
    balance_lookback, balance_round, effective_key_dilution, params_round, seed_round,
};
pub use proposal::{payout_eligible, verify_proposer, ProposalError, UnauthenticatedProposal};
pub use seed::{
    derive_seed_period_nonzero, derive_seed_period_zero, history_mix_round, ProposerSeed, Seed,
    SeedInput, VrfOutput,
};
pub use selector::Selector;
pub use step::{Period, Step, CERT, DOWN, LATE, NEXT, PROPOSE, REDO, SOFT};
pub use stubs::{
    EventsQueueUpdate, SentMessage, StubBlockFactory, StubBlockValidator,
    StubEventsProcessingMonitor, StubLedger, StubNetwork, StubRandomSource, StubUnfinishedBlock,
    StubValidatedBlock, WrittenBlock,
};
pub use traits::{
    AgreementError, AgreementKeyManager, AgreementLedger, AgreementNetwork, BlockFactory,
    BlockValidator, EventsProcessingMonitor, LedgerWriter, Message, MessageHandle,
    ParticipationAction, ParticipationRecord, RandomSource, Tag, UnfinishedBlock, ValidatedBlock,
    AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
pub use vote::{
    ProposalValue, RawVote, UnauthenticatedVote, Vote, VoteError, VoteVerifyParams, BOTTOM,
};

// Re-exports from new modules
pub use actions::{
    Action, ActionType, CheckpointAction, CryptoAction, EnsureAction, NetworkAction, NoopAction,
    PseudonodeAction, RezeroAction, StageDigestAction,
};
pub use events::{
    CheckpointEvent, CommittableEvent, CompoundMessage, ConsensusVersionView, DumpVotesEvent,
    DumpVotesRequestEvent, EmptyEvent, Event, EventType, FilterableMessageEvent, FilteredEvent,
    FilteredStepEvent, FreshestBundleEvent, FreshestBundleRequestEvent, InternalMessage,
    LateCredentialTrackingEffect, MessageEvent, NewPeriodEvent, NewRoundEvent,
    NextThresholdStatusEvent, NextThresholdStatusRequestEvent, PayloadProcessedEvent,
    PinnedValueEvent, Proposal, ProposalAcceptedEvent, ProposalFrozenEvent, ReadLowestEvent,
    RoundInterruptionEvent, SerializableError, StagingValueEvent, ThresholdEvent, TimeoutEvent,
    VoteAcceptedEvent, VoteFilterRequestEvent, PIPELINED_MESSAGE_TIMESTAMP,
};
pub use pseudonode::{AsyncPseudonode, Pseudonode, PseudonodeError};
pub use types::{
    CredentialArrivalHistory, Deadline, TimeoutType, BIG_LAMBDA, DEFAULT_DEADLINE_TIMEOUT,
    DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
    DYNAMIC_FILTER_TIMEOUT_CREDENTIAL_ARRIVAL_HISTORY_IDX, DYNAMIC_FILTER_TIMEOUT_GRACE_INTERVAL,
    DYNAMIC_FILTER_TIMEOUT_LOWER_BOUND, PARTITION_STEP, RECOVERY_EXTRA_TIMEOUT, SMALL_LAMBDA,
};

// Re-exports from proposal subsystem modules
pub use proposal_manager::ProposalManager;
pub use proposal_store::{BlockAssembler, ProposalStore};
pub use proposal_tracker::{ProposalSeeker, ProposalTracker};

// Re-exports from vote subsystem modules
pub use vote_aggregator::VoteAggregator;
pub use vote_auxiliary::{VoteTrackerPeriod, VoteTrackerRound};
pub use vote_tracker::{EquivocationVote, VoteTracker};

// Re-exports from router, demux, and player modules
pub use demux::{Demux, ExternalDemuxSignals, ExternalEvent};
pub use player::{Player, Tracer};
pub use router::{PeriodRouter, RootRouter, RoundRouter, StateMachineTag, StepRouter};
