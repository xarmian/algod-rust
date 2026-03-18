// Stub/mock implementations of agreement traits for unit testing.
//
// These stubs are configurable and record their interactions so tests
// can verify the agreement state machine's behavior.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use algo_types::{Address, Block, ConsensusParams, Digest, Round};

use crate::certificate::Certificate;
use crate::ledger_reader::{LedgerError, LedgerReader, OnlineAccountData};
use crate::seed::Seed;
use crate::traits::{
    AgreementError, AgreementNetwork, AsyncVoteVerifier, BlockFactory, BlockValidator,
    CryptoBundleRequest, CryptoProposalRequest, CryptoResult, CryptoVerifier, CryptoVoteRequest,
    CryptoVoteVerifyResult, EventsProcessingMonitor, LedgerWriter, Message, MessageHandle,
    RandomSource, Tag, UnfinishedBlock, ValidatedBlock, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};

// ---------------------------------------------------------------------------
// StubValidatedBlock
// ---------------------------------------------------------------------------

/// A simple `ValidatedBlock` wrapping a `Block`.
#[derive(Debug, Clone)]
pub struct StubValidatedBlock {
    pub block: Block,
}

impl ValidatedBlock for StubValidatedBlock {
    fn block(&self) -> &Block {
        &self.block
    }
}

// ---------------------------------------------------------------------------
// StubUnfinishedBlock
// ---------------------------------------------------------------------------

/// A stub `UnfinishedBlock` that returns a pre-configured block from
/// `finish_block`, recording the arguments for test assertions.
#[derive(Debug, Clone)]
pub struct StubUnfinishedBlock {
    /// The block to return from `finish_block`.
    pub block: Block,
    /// The round this unfinished block is for.
    pub rnd: Round,
    /// Records the arguments passed to `finish_block` (seed, proposer, eligible).
    pub finish_args: RefCell<Option<(Seed, Address, bool)>>,
}

impl StubUnfinishedBlock {
    /// Creates a new `StubUnfinishedBlock` with the given block and round.
    pub fn new(block: Block, rnd: Round) -> Self {
        Self {
            block,
            rnd,
            finish_args: RefCell::new(None),
        }
    }

    /// Returns the arguments that were passed to `finish_block`, if any.
    pub fn get_finish_args(&self) -> Option<(Seed, Address, bool)> {
        *self.finish_args.borrow()
    }
}

impl UnfinishedBlock for StubUnfinishedBlock {
    fn finish_block(&self, seed: Seed, proposer: Address, eligible: bool) -> Block {
        *self.finish_args.borrow_mut() = Some((seed, proposer, eligible));
        self.block.clone()
    }

    fn round(&self) -> Round {
        self.rnd
    }
}

// ---------------------------------------------------------------------------
// StubBlockValidator
// ---------------------------------------------------------------------------

/// A configurable `BlockValidator` for testing.
///
/// When `accept` is true, all blocks are accepted. When false, all blocks
/// are rejected with the configured `reject_reason`.
pub struct StubBlockValidator {
    /// Whether to accept blocks.
    pub accept: bool,
    /// The error message to use when rejecting.
    pub reject_reason: String,
}

impl StubBlockValidator {
    /// Creates a validator that accepts all blocks.
    pub fn accepting() -> Self {
        Self {
            accept: true,
            reject_reason: String::new(),
        }
    }

    /// Creates a validator that rejects all blocks with the given reason.
    pub fn rejecting(reason: &str) -> Self {
        Self {
            accept: false,
            reject_reason: reason.to_string(),
        }
    }
}

impl BlockValidator for StubBlockValidator {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        if self.accept {
            Ok(Box::new(StubValidatedBlock {
                block: block.clone(),
            }))
        } else {
            Err(AgreementError::ValidationFailed(self.reject_reason.clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// StubBlockFactory
// ---------------------------------------------------------------------------

/// A configurable `BlockFactory` that returns pre-configured blocks.
///
/// Blocks are configured per-round. If no block is configured for a round,
/// `assemble_block` returns `AgreementError::RoundStale`.
pub struct StubBlockFactory {
    /// Pre-configured blocks by round.
    pub blocks: HashMap<Round, Block>,
}

impl StubBlockFactory {
    /// Creates an empty factory (all rounds will fail).
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
        }
    }

    /// Adds a block for the given round.
    pub fn set_block(&mut self, round: Round, block: Block) {
        self.blocks.insert(round, block);
    }
}

impl Default for StubBlockFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockFactory for StubBlockFactory {
    fn assemble_block(
        &self,
        round: Round,
        _addresses: &[Address],
    ) -> Result<Box<dyn UnfinishedBlock>, AgreementError> {
        match self.blocks.get(&round) {
            Some(block) => Ok(Box::new(StubUnfinishedBlock::new(block.clone(), round))),
            None => Err(AgreementError::RoundStale(round)),
        }
    }
}

// ---------------------------------------------------------------------------
// StubLedger
// ---------------------------------------------------------------------------

/// A record of a block written to the stub ledger via `ensure_block`.
#[derive(Debug, Clone)]
pub struct WrittenBlock {
    pub block: Block,
    pub cert: Certificate,
}

/// A configurable stub that implements both `LedgerReader` and `LedgerWriter`.
///
/// Configurable:
/// - `next_rnd`: the next round (latest certified + 1)
/// - `seeds`: per-round seeds
/// - `accounts`: per-round per-address account data
/// - `circulation`: per-round total online circulation
/// - `digests`: per-round block digests
/// - `params`: consensus params (same for all rounds unless overridden)
/// - `consensus_ver`: protocol version string
///
/// Records what was written via `ensure_block` for test assertions.
pub struct StubLedger {
    /// The next round (latest certified + 1).
    pub next_rnd: Round,
    /// Seeds by round.
    pub seeds: HashMap<Round, Seed>,
    /// Account data by (round, address).
    pub accounts: HashMap<(Round, Address), OnlineAccountData>,
    /// Total online circulation by round.
    pub circulation_by_round: HashMap<Round, u64>,
    /// Default circulation (used when round not in map).
    pub default_circulation: u64,
    /// Block digests by round.
    pub digests: HashMap<Round, Digest>,
    /// Consensus parameters (used for all rounds).
    pub params: ConsensusParams,
    /// Per-round consensus params overrides.
    pub params_by_round: HashMap<Round, ConsensusParams>,
    /// Protocol version string.
    pub consensus_ver: String,
    /// Blocks written via `ensure_block` / `ensure_validated_block`.
    pub written_blocks: Mutex<Vec<WrittenBlock>>,
    /// Certificates passed to `ensure_digest`.
    pub ensured_digests: Mutex<Vec<Certificate>>,
    /// Pending round notification waiters: (requested_round, sender).
    /// Protected by a Mutex so `round_notify(&self)` can push entries.
    round_waiters: Mutex<Vec<(Round, crossbeam_channel::Sender<Round>)>>,
}

impl StubLedger {
    /// Creates a new stub ledger with the given params and next round.
    pub fn new(params: ConsensusParams, next_rnd: Round) -> Self {
        Self {
            next_rnd,
            seeds: HashMap::new(),
            accounts: HashMap::new(),
            circulation_by_round: HashMap::new(),
            default_circulation: 10_000_000,
            digests: HashMap::new(),
            params,
            params_by_round: HashMap::new(),
            consensus_ver: algo_types::CONSENSUS_V41.to_string(),
            written_blocks: Mutex::new(Vec::new()),
            ensured_digests: Mutex::new(Vec::new()),
            round_waiters: Mutex::new(Vec::new()),
        }
    }

    /// Adds a seed for the given round.
    pub fn set_seed(&mut self, round: Round, seed: Seed) {
        self.seeds.insert(round, seed);
    }

    /// Adds account data for the given round and address.
    pub fn set_account(&mut self, round: Round, addr: Address, data: OnlineAccountData) {
        self.accounts.insert((round, addr), data);
    }

    /// Sets the circulation for a specific round.
    pub fn set_circulation(&mut self, round: Round, amount: u64) {
        self.circulation_by_round.insert(round, amount);
    }

    /// Sets the block digest for a specific round.
    pub fn set_digest(&mut self, round: Round, digest: Digest) {
        self.digests.insert(round, digest);
    }

    /// Sets consensus params for a specific round.
    pub fn set_params_for_round(&mut self, round: Round, params: ConsensusParams) {
        self.params_by_round.insert(round, params);
    }

    /// Returns the blocks that have been written via `ensure_block`.
    pub fn get_written_blocks(&self) -> Vec<WrittenBlock> {
        self.written_blocks.lock().unwrap().clone()
    }

    /// Returns the certificates that were passed to `ensure_digest`.
    pub fn get_ensured_digests(&self) -> Vec<Certificate> {
        self.ensured_digests.lock().unwrap().clone()
    }

    /// Advance the stub ledger to the given round and fire any pending
    /// round-notify waiters whose requested round has been reached.
    ///
    /// This is a test helper that mirrors the real ledger's round advancement
    /// triggered by `ensure_block`.
    pub fn advance_round(&mut self, new_next_round: Round) {
        self.next_rnd = new_next_round;

        // Drain waiters whose requested round is now available
        // (i.e., requested_round < new_next_round, since next_round = latest + 1).
        let mut waiters = self.round_waiters.lock().unwrap();
        waiters.retain(|(requested_round, sender)| {
            if requested_round.0 < new_next_round.0 {
                // Round is available — fire the notification.
                let _ = sender.send(*requested_round);
                false // remove from list
            } else {
                true // keep waiting
            }
        });
    }
}

impl LedgerReader for StubLedger {
    fn seed(&self, round: Round) -> Result<Seed, LedgerError> {
        self.seeds
            .get(&round)
            .copied()
            .ok_or(LedgerError::RoundNotAvailable(round))
    }

    fn lookup_agreement(
        &self,
        round: Round,
        addr: &Address,
    ) -> Result<OnlineAccountData, LedgerError> {
        self.accounts
            .get(&(round, *addr))
            .cloned()
            .ok_or(LedgerError::Other(format!(
                "account {addr:?} not found at round {round}"
            )))
    }

    fn circulation(&self, rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
        Ok(*self
            .circulation_by_round
            .get(&rnd)
            .unwrap_or(&self.default_circulation))
    }

    fn lookup_digest(&self, round: Round) -> Result<Digest, LedgerError> {
        self.digests
            .get(&round)
            .copied()
            .ok_or(LedgerError::RoundNotAvailable(round))
    }

    fn consensus_params(&self, round: Round) -> Result<ConsensusParams, LedgerError> {
        if let Some(p) = self.params_by_round.get(&round) {
            Ok(p.clone())
        } else {
            Ok(self.params.clone())
        }
    }

    fn next_round(&self) -> Round {
        self.next_rnd
    }

    fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
        Ok(self.consensus_ver.clone())
    }

    fn wait_for_round(&self, round: Round) -> Result<(), LedgerError> {
        if round.0 < self.next_rnd.0 {
            Ok(())
        } else {
            Err(LedgerError::RoundNotAvailable(round))
        }
    }

    fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
        // If the round is already available, return an immediately-ready channel.
        if round.0 < self.next_rnd.0 {
            let (tx, rx) = crossbeam_channel::bounded(1);
            let _ = tx.send(round);
            return rx;
        }
        // Otherwise register a waiter that will be fired when advance_round is called.
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.round_waiters.lock().unwrap().push((round, tx));
        rx
    }
}

impl LedgerWriter for StubLedger {
    fn ensure_block(&self, block: &Block, cert: &Certificate) {
        self.written_blocks.lock().unwrap().push(WrittenBlock {
            block: block.clone(),
            cert: cert.clone(),
        });
    }

    fn ensure_validated_block(&self, vb: &dyn ValidatedBlock, cert: &Certificate) {
        self.ensure_block(vb.block(), cert);
    }

    fn ensure_digest(&self, cert: &Certificate, _verifier: &AsyncVoteVerifier) {
        self.ensured_digests.lock().unwrap().push(cert.clone());
    }
}

// ---------------------------------------------------------------------------
// StubRandomSource
// ---------------------------------------------------------------------------

/// A deterministic `RandomSource` that returns values from a pre-configured
/// sequence, cycling when exhausted.
pub struct StubRandomSource {
    values: Vec<u64>,
    index: RefCell<usize>,
}

impl StubRandomSource {
    /// Creates a new stub random source with the given sequence of values.
    ///
    /// Panics if `values` is empty.
    pub fn new(values: Vec<u64>) -> Self {
        assert!(
            !values.is_empty(),
            "StubRandomSource needs at least one value"
        );
        Self {
            values,
            index: RefCell::new(0),
        }
    }

    /// Creates a stub that always returns the same value.
    pub fn constant(value: u64) -> Self {
        Self::new(vec![value])
    }
}

impl RandomSource for StubRandomSource {
    fn uint64(&self) -> u64 {
        let mut idx = self.index.borrow_mut();
        let val = self.values[*idx % self.values.len()];
        *idx += 1;
        val
    }
}

// ---------------------------------------------------------------------------
// StubNetwork
// ---------------------------------------------------------------------------

/// A record of a message sent via `broadcast` or `relay`.
#[derive(Debug, Clone)]
pub struct SentMessage {
    /// The protocol tag.
    pub tag: Tag,
    /// The payload.
    pub data: Vec<u8>,
    /// Whether this was a relay (true) or broadcast (false).
    pub is_relay: bool,
}

/// A configurable `AgreementNetwork` stub for testing.
///
/// Records all sent messages (broadcasts and relays) and provides injectable
/// inbound message channels.
pub struct StubNetwork {
    /// Messages sent via `broadcast` or `relay`.
    pub sent: Mutex<Vec<SentMessage>>,
    /// Handles that were disconnected.
    pub disconnected: Mutex<Vec<()>>,
    /// Whether `start` has been called.
    pub started: Mutex<bool>,
    /// Senders for injecting inbound messages, keyed by tag.
    inbound_senders: Mutex<HashMap<&'static str, crossbeam_channel::Sender<Message>>>,
    /// Receivers for inbound messages, keyed by tag.
    /// Each tag's receiver is created on first call to `messages()`.
    inbound_receivers: Mutex<HashMap<&'static str, crossbeam_channel::Receiver<Message>>>,
}

impl StubNetwork {
    /// Creates a new stub network.
    pub fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            disconnected: Mutex::new(Vec::new()),
            started: Mutex::new(false),
            inbound_senders: Mutex::new(HashMap::new()),
            inbound_receivers: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a sender that can be used to inject inbound messages for the
    /// given tag. Creates the channel if it does not already exist.
    pub fn inject_sender(&self, tag: &Tag) -> crossbeam_channel::Sender<Message> {
        let mut senders = self.inbound_senders.lock().unwrap();
        if let Some(sender) = senders.get(tag.0) {
            return sender.clone();
        }
        let (tx, rx) = crossbeam_channel::unbounded();
        senders.insert(tag.0, tx.clone());
        self.inbound_receivers.lock().unwrap().insert(tag.0, rx);
        tx
    }

    /// Returns all sent messages.
    pub fn get_sent(&self) -> Vec<SentMessage> {
        self.sent.lock().unwrap().clone()
    }
}

impl Default for StubNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementNetwork for StubNetwork {
    fn messages(&self, tag: &Tag) -> crossbeam_channel::Receiver<Message> {
        // If a receiver already exists, take it out (can only be called once per tag).
        if let Some(rx) = self.inbound_receivers.lock().unwrap().remove(tag.0) {
            return rx;
        }
        // Otherwise create a new channel and store the sender.
        let (tx, rx) = crossbeam_channel::unbounded();
        self.inbound_senders.lock().unwrap().insert(tag.0, tx);
        rx
    }

    fn broadcast(&self, tag: &Tag, data: &[u8]) -> Result<(), AgreementError> {
        self.sent.lock().unwrap().push(SentMessage {
            tag: tag.clone(),
            data: data.to_vec(),
            is_relay: false,
        });
        Ok(())
    }

    fn relay(&self, _handle: &MessageHandle, tag: &Tag, data: &[u8]) -> Result<(), AgreementError> {
        self.sent.lock().unwrap().push(SentMessage {
            tag: tag.clone(),
            data: data.to_vec(),
            is_relay: true,
        });
        Ok(())
    }

    fn disconnect(&self, _handle: &MessageHandle) {
        self.disconnected.lock().unwrap().push(());
    }

    fn start(&self) {
        *self.started.lock().unwrap() = true;
    }
}

// ---------------------------------------------------------------------------
// StubEventsProcessingMonitor
// ---------------------------------------------------------------------------

/// A record of a single `update_events_queue` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventsQueueUpdate {
    /// The name of the queue that was updated.
    pub queue_name: String,
    /// The reported queue length.
    pub queue_length: usize,
}

/// A stub `EventsProcessingMonitor` that records all calls for test assertions.
pub struct StubEventsProcessingMonitor {
    /// All recorded queue updates.
    pub updates: RefCell<Vec<EventsQueueUpdate>>,
}

impl StubEventsProcessingMonitor {
    /// Creates a new monitor with no recorded updates.
    pub fn new() -> Self {
        Self {
            updates: RefCell::new(Vec::new()),
        }
    }

    /// Returns a snapshot of all recorded updates.
    pub fn get_updates(&self) -> Vec<EventsQueueUpdate> {
        self.updates.borrow().clone()
    }
}

impl Default for StubEventsProcessingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl EventsProcessingMonitor for StubEventsProcessingMonitor {
    fn update_events_queue(&self, queue_name: &str, queue_length: usize) {
        self.updates.borrow_mut().push(EventsQueueUpdate {
            queue_name: queue_name.to_string(),
            queue_length,
        });
    }
}

// ---------------------------------------------------------------------------
// StubCryptoVerifier
// ---------------------------------------------------------------------------

/// A synchronous stub `CryptoVerifier` for testing.
///
/// Performs no actual cryptographic verification. Votes are accepted
/// immediately and pushed onto the output channel. Proposals and bundles
/// are similarly passed through with no verification.
pub struct StubCryptoVerifier {
    /// Channel pair for vote verification results.
    vote_tx: crossbeam_channel::Sender<CryptoVoteVerifyResult>,
    vote_rx: crossbeam_channel::Receiver<CryptoVoteVerifyResult>,

    /// Channel pair for proposal verification results.
    proposal_tx: crossbeam_channel::Sender<CryptoResult>,
    proposal_rx: crossbeam_channel::Receiver<CryptoResult>,

    /// Channel pair for bundle verification results.
    bundle_tx: crossbeam_channel::Sender<CryptoResult>,
    bundle_rx: crossbeam_channel::Receiver<CryptoResult>,
}

impl StubCryptoVerifier {
    /// Creates a new stub crypto verifier with unbounded channels.
    pub fn new() -> Self {
        let (vote_tx, vote_rx) = crossbeam_channel::unbounded();
        let (proposal_tx, proposal_rx) = crossbeam_channel::unbounded();
        let (bundle_tx, bundle_rx) = crossbeam_channel::unbounded();
        Self {
            vote_tx,
            vote_rx,
            proposal_tx,
            proposal_rx,
            bundle_tx,
            bundle_rx,
        }
    }
}

impl Default for StubCryptoVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoVerifier for StubCryptoVerifier {
    fn verify_vote(&self, request: CryptoVoteRequest) {
        // Synchronous pass-through: immediately produce a successful result.
        let result = CryptoVoteVerifyResult {
            // In a real verifier, the vote field would be set to the verified
            // vote. The stub leaves it as the already-authenticated vote from
            // the message (if present).
            vote: request.message.vote.clone(),
            message: request.message,
            task_index: request.task_index,
            err: None,
            cancelled: false,
        };
        let _ = self.vote_tx.send(result);
    }

    fn verify_proposal(&self, request: CryptoProposalRequest) {
        let result = CryptoResult {
            message: request.message,
            task_index: request.task_index,
            err: None,
            cancelled: false,
        };
        let _ = self.proposal_tx.send(result);
    }

    fn verify_bundle(&self, request: CryptoBundleRequest) {
        let result = CryptoResult {
            message: request.message,
            task_index: request.task_index,
            err: None,
            cancelled: false,
        };
        let _ = self.bundle_tx.send(result);
    }

    fn verified_votes(&self) -> &crossbeam_channel::Receiver<CryptoVoteVerifyResult> {
        &self.vote_rx
    }

    fn verified(&self, tag: &str) -> &crossbeam_channel::Receiver<CryptoResult> {
        match tag {
            PROPOSAL_PAYLOAD_TAG => &self.proposal_rx,
            VOTE_BUNDLE_TAG => &self.bundle_rx,
            _ => panic!("StubCryptoVerifier::verified called with unknown tag: {tag}"),
        }
    }

    fn channel_full(&self, _tag: &str) -> bool {
        // Unbounded channels are never full.
        false
    }

    fn quit(&self) {
        // No background workers to shut down in the stub.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::Period;
    use crate::vote::ProposalValue;

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    fn make_default_block() -> Block {
        Block::default()
    }

    fn make_certificate(round: Round) -> Certificate {
        Certificate {
            round,
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        }
    }

    // -- StubValidatedBlock --

    #[test]
    fn stub_validated_block_returns_block() {
        let block = make_default_block();
        let vb = StubValidatedBlock {
            block: block.clone(),
        };
        // ValidatedBlock::block() should return a reference to the stored block
        let _ = vb.block();
    }

    // -- StubUnfinishedBlock --

    #[test]
    fn stub_unfinished_block_round() {
        let ub = StubUnfinishedBlock::new(make_default_block(), Round(42));
        assert_eq!(ub.round(), Round(42));
    }

    #[test]
    fn stub_unfinished_block_finish_records_args() {
        let ub = StubUnfinishedBlock::new(make_default_block(), Round(42));
        assert!(ub.get_finish_args().is_none());

        let seed = Seed([0xab; 32]);
        let proposer = Address([0x01; 32]);
        let _finished = ub.finish_block(seed, proposer, true);

        let args = ub.get_finish_args().expect("should record args");
        assert_eq!(args.0, seed);
        assert_eq!(args.1, proposer);
        assert!(args.2);
    }

    // -- StubBlockValidator --

    #[test]
    fn stub_block_validator_accepts() {
        let validator = StubBlockValidator::accepting();
        let block = make_default_block();
        let result = validator.validate(&block);
        assert!(result.is_ok());
    }

    #[test]
    fn stub_block_validator_rejects() {
        let validator = StubBlockValidator::rejecting("invalid txn");
        let block = make_default_block();
        let result = validator.validate(&block);
        assert!(result.is_err());
        let err = result.err().expect("should be Err");
        assert!(
            format!("{err}").contains("invalid txn"),
            "error should contain reject reason"
        );
    }

    // -- StubBlockFactory --

    #[test]
    fn stub_block_factory_returns_configured_block() {
        let mut factory = StubBlockFactory::new();
        let block = make_default_block();
        factory.set_block(Round(10), block);

        let result = factory.assemble_block(Round(10), &[]);
        assert!(result.is_ok());
        let ub = result.unwrap();
        assert_eq!(ub.round(), Round(10));
    }

    #[test]
    fn stub_block_factory_returns_error_for_unconfigured_round() {
        let factory = StubBlockFactory::new();
        let result = factory.assemble_block(Round(99), &[]);
        assert!(result.is_err());
    }

    // -- StubLedger (LedgerReader) --

    #[test]
    fn stub_ledger_next_round() {
        let ledger = StubLedger::new(v41_params(), Round(42));
        assert_eq!(ledger.next_round(), Round(42));
    }

    #[test]
    fn stub_ledger_seed() {
        let mut ledger = StubLedger::new(v41_params(), Round(1));
        ledger.set_seed(Round(5), Seed([0xab; 32]));

        assert!(ledger.seed(Round(5)).is_ok());
        assert_eq!(ledger.seed(Round(5)).unwrap(), Seed([0xab; 32]));
        assert!(ledger.seed(Round(6)).is_err());
    }

    #[test]
    fn stub_ledger_lookup_agreement() {
        let mut ledger = StubLedger::new(v41_params(), Round(1));
        let addr = Address([0x42; 32]);
        let data = OnlineAccountData {
            micro_algos: 5_000_000,
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 0,
            incentive_eligible: false,
            last_proposed: Round(0),
            last_heartbeat: Round(0),
            state_proof_id: [0u8; 64],
        };
        ledger.set_account(Round(10), addr, data.clone());

        let result = ledger.lookup_agreement(Round(10), &addr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().micro_algos, 5_000_000);

        // Different round should fail
        assert!(ledger.lookup_agreement(Round(11), &addr).is_err());
    }

    #[test]
    fn stub_ledger_circulation() {
        let mut ledger = StubLedger::new(v41_params(), Round(1));
        ledger.set_circulation(Round(5), 99_000_000);

        assert_eq!(
            ledger.circulation(Round(5), Round(100)).unwrap(),
            99_000_000
        );
        // Unconfigured round uses default
        assert_eq!(
            ledger.circulation(Round(6), Round(100)).unwrap(),
            10_000_000
        );
    }

    #[test]
    fn stub_ledger_consensus_version() {
        let ledger = StubLedger::new(v41_params(), Round(1));
        let ver = ledger.consensus_version(Round(1)).unwrap();
        assert_eq!(ver, algo_types::CONSENSUS_V41);
    }

    #[test]
    fn stub_ledger_wait_for_round() {
        let ledger = StubLedger::new(v41_params(), Round(10));
        // Rounds before next_round should succeed
        assert!(ledger.wait_for_round(Round(5)).is_ok());
        assert!(ledger.wait_for_round(Round(9)).is_ok());
        // Round at or after next_round should fail
        assert!(ledger.wait_for_round(Round(10)).is_err());
        assert!(ledger.wait_for_round(Round(100)).is_err());
    }

    #[test]
    fn stub_ledger_consensus_params_override() {
        let params = v41_params();
        let mut ledger = StubLedger::new(params.clone(), Round(1));

        let mut custom = params.clone();
        custom.min_txn_fee = 9999;
        ledger.set_params_for_round(Round(42), custom.clone());

        // Default round
        assert_eq!(
            ledger.consensus_params(Round(1)).unwrap().min_txn_fee,
            params.min_txn_fee
        );
        // Overridden round
        assert_eq!(
            ledger.consensus_params(Round(42)).unwrap().min_txn_fee,
            9999
        );
    }

    // -- StubLedger (LedgerWriter) --

    #[test]
    fn stub_ledger_ensure_block_records() {
        let ledger = StubLedger::new(v41_params(), Round(1));
        let block = make_default_block();
        let cert = make_certificate(Round(1));

        ledger.ensure_block(&block, &cert);

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].cert.round, Round(1));
    }

    #[test]
    fn stub_ledger_ensure_validated_block_records() {
        let ledger = StubLedger::new(v41_params(), Round(1));
        let block = make_default_block();
        let vb = StubValidatedBlock {
            block: block.clone(),
        };
        let cert = make_certificate(Round(1));

        ledger.ensure_validated_block(&vb, &cert);

        let written = ledger.get_written_blocks();
        assert_eq!(written.len(), 1);
    }

    #[test]
    fn stub_ledger_ensure_digest_records() {
        let ledger = StubLedger::new(v41_params(), Round(1));
        let cert = make_certificate(Round(5));
        let verifier = AsyncVoteVerifier::new();

        ledger.ensure_digest(&cert, &verifier);

        let ensured = ledger.get_ensured_digests();
        assert_eq!(ensured.len(), 1);
        assert_eq!(ensured[0].round, Round(5));
    }

    #[test]
    fn stub_ledger_is_agreement_ledger() {
        // Compile-time check: StubLedger implements AgreementLedger
        fn _assert<T: crate::traits::AgreementLedger>() {}
        _assert::<StubLedger>();
    }

    // -- StubRandomSource --

    #[test]
    fn stub_random_source_constant() {
        let rng = StubRandomSource::constant(42);
        assert_eq!(rng.uint64(), 42);
        assert_eq!(rng.uint64(), 42);
        assert_eq!(rng.uint64(), 42);
    }

    #[test]
    fn stub_random_source_sequence() {
        let rng = StubRandomSource::new(vec![10, 20, 30]);
        assert_eq!(rng.uint64(), 10);
        assert_eq!(rng.uint64(), 20);
        assert_eq!(rng.uint64(), 30);
        // Cycles
        assert_eq!(rng.uint64(), 10);
    }

    #[test]
    #[should_panic(expected = "at least one value")]
    fn stub_random_source_empty_panics() {
        let _ = StubRandomSource::new(vec![]);
    }

    // -- StubEventsProcessingMonitor --

    #[test]
    fn stub_events_monitor_records_updates() {
        let monitor = StubEventsProcessingMonitor::new();
        assert!(monitor.get_updates().is_empty());

        monitor.update_events_queue("cryptoVerifier", 5);
        monitor.update_events_queue("demux", 12);

        let updates = monitor.get_updates();
        assert_eq!(updates.len(), 2);
        assert_eq!(
            updates[0],
            EventsQueueUpdate {
                queue_name: "cryptoVerifier".to_string(),
                queue_length: 5,
            }
        );
        assert_eq!(
            updates[1],
            EventsQueueUpdate {
                queue_name: "demux".to_string(),
                queue_length: 12,
            }
        );
    }

    #[test]
    fn stub_events_monitor_default() {
        let monitor = StubEventsProcessingMonitor::default();
        assert!(monitor.get_updates().is_empty());
    }

    // -- StubCryptoVerifier --

    #[test]
    fn stub_crypto_verifier_vote_passthrough() {
        use crate::events::InternalMessage;
        use crate::traits::CryptoVoteRequest;
        use crate::vote::UnauthenticatedVote;

        let verifier = StubCryptoVerifier::new();

        let request = CryptoVoteRequest {
            message: InternalMessage {
                tag: "AV".to_string(),
                unauthenticated_vote: UnauthenticatedVote::default(),
                ..InternalMessage::default()
            },
            task_index: 42,
            round: Round(10),
            period: Period(0),
        };

        verifier.verify_vote(request);

        // Result should be immediately available on the channel.
        let result = verifier
            .verified_votes()
            .try_recv()
            .expect("should have a result");
        assert_eq!(result.task_index, 42);
        assert!(result.err.is_none());
        assert!(!result.cancelled);
    }

    #[test]
    fn stub_crypto_verifier_proposal_passthrough() {
        use crate::events::InternalMessage;
        use crate::traits::{CryptoProposalRequest, PROPOSAL_PAYLOAD_TAG};

        let verifier = StubCryptoVerifier::new();

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 7,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .try_recv()
            .expect("should have a result");
        assert_eq!(result.task_index, 7);
        assert!(result.err.is_none());
        assert!(!result.cancelled);
    }

    #[test]
    fn stub_crypto_verifier_bundle_passthrough() {
        use crate::events::InternalMessage;
        use crate::traits::{CryptoBundleRequest, VOTE_BUNDLE_TAG};

        let verifier = StubCryptoVerifier::new();

        let request = CryptoBundleRequest {
            message: InternalMessage {
                tag: "VB".to_string(),
                ..InternalMessage::default()
            },
            task_index: 99,
            round: Round(20),
            period: Period(1),
            certify: true,
        };

        verifier.verify_bundle(request);

        let result = verifier
            .verified(VOTE_BUNDLE_TAG)
            .try_recv()
            .expect("should have a result");
        assert_eq!(result.task_index, 99);
        assert!(result.err.is_none());
        assert!(!result.cancelled);
    }

    #[test]
    fn stub_crypto_verifier_channel_never_full() {
        let verifier = StubCryptoVerifier::new();
        assert!(!verifier.channel_full("AV"));
        assert!(!verifier.channel_full("PP"));
        assert!(!verifier.channel_full("VB"));
    }

    #[test]
    fn stub_crypto_verifier_is_crypto_verifier() {
        // Compile-time check: StubCryptoVerifier implements CryptoVerifier
        fn _assert<T: CryptoVerifier>() {}
        _assert::<StubCryptoVerifier>();
    }
}
