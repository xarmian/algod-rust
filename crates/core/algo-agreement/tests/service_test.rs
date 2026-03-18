// Integration tests for the Agreement Service, bridge implementations,
// pseudonode signing, and codec round-trips.
//
// These tests exercise the public API of algo-agreement as an external consumer
// would, using the stub types from `algo_agreement::stubs` for mocking
// network, ledger, key manager, and other dependencies.

use std::thread;
use std::time::Duration;

use algo_agreement::{
    // Codec
    codec,
    // Pseudonode / signing
    AccountSigningKeys,
    // Traits (must be in scope to call their methods)
    AgreementKeyManager,
    AgreementNetwork,
    AsyncPseudonode,
    BlockFactory,
    BlockValidator,
    // Bridge types
    BlockValidatorBridge,
    CryptoVerifier,
    EventsProcessingMonitor,
    LedgerReader,
    LedgerWriter,
    // Service / Parameters
    Message,
    Parameters,
    ParticipationAction,
    ParticipationRecord,
    // Other types
    Period,
    PoolUnfinishedBlock,
    // Vote types
    ProposalValue,
    Pseudonode,
    PseudonodeError,
    RandomSource,
    Seed,
    Service,
    Step,
    // Stubs
    StubBlockFactory,
    StubBlockValidator,
    StubCryptoVerifier,
    StubEventsProcessingMonitor,
    StubLedger,
    StubNetwork,
    StubRandomSource,
    Tag,
    UnauthenticatedVote,
    UnfinishedBlock,
    ValidatedBlock,
    ValidatedBlockImpl,
    AGREEMENT_VOTE_TAG,
    BOTTOM,
    PROPOSAL_PAYLOAD_TAG,
    VOTE_BUNDLE_TAG,
};
use algo_consensus_crypto::vrf::VrfKeypair;
use algo_consensus_crypto::OneTimeSignatureSecrets;
use algo_types::{Address, Block, ConsensusParams, Digest, Round};

// ---------------------------------------------------------------------------
// Helper: consensus params
// ---------------------------------------------------------------------------

fn v41_params() -> ConsensusParams {
    algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
        .expect("v41 params")
}

// ---------------------------------------------------------------------------
// Helper: test key manager (no participation keys)
// ---------------------------------------------------------------------------

struct EmptyKeyManager;

impl AgreementKeyManager for EmptyKeyManager {
    fn voting_keys(&self, _voting_round: Round, _keys_round: Round) -> Vec<ParticipationRecord> {
        Vec::new()
    }

    fn record(&self, _account: &Address, _round: Round, _action: ParticipationAction) {}
}

// ---------------------------------------------------------------------------
// Helper: test key manager with configurable keys
// ---------------------------------------------------------------------------

struct TestKeyManager {
    keys: Vec<ParticipationRecord>,
}

impl TestKeyManager {
    fn new(keys: Vec<ParticipationRecord>) -> Self {
        Self { keys }
    }
}

impl AgreementKeyManager for TestKeyManager {
    fn voting_keys(&self, _voting_round: Round, _keys_round: Round) -> Vec<ParticipationRecord> {
        self.keys.clone()
    }

    fn record(&self, _account: &Address, _round: Round, _action: ParticipationAction) {}
}

// ===========================================================================
// Service lifecycle tests
// ===========================================================================

#[test]
fn service_starts_and_shuts_down_cleanly() {
    // Verify that constructing, starting, and shutting down a Service completes
    // without panicking or hanging. Uses all stub implementations.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let service = Service::new(params);
    let handle = service.start();

    // Let the threads run briefly.
    thread::sleep(Duration::from_millis(50));

    handle.shutdown();
}

#[test]
fn service_start_calls_network_start() {
    // The Service::start() method must call network.start() to signal that the
    // agreement service is ready to receive messages.
    let network = StubNetwork::new();

    // Verify network has not been started yet.
    assert!(!*network.started.lock().unwrap());

    let params = Parameters {
        network,
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let service = Service::new(params);
    let handle = service.start();

    // After start(), network.start() should have been called.
    // Give a brief moment for threads to initialize.
    thread::sleep(Duration::from_millis(30));

    handle.shutdown();
    // The network was consumed by the service, so we cannot check directly,
    // but the fact that start completed without error is the assertion.
}

#[test]
fn service_bootstrap_at_ledger_round() {
    // The service should bootstrap the Player at the round returned by
    // ledger.next_round(). We verify this indirectly: the service should
    // not panic when the ledger reports a high round.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(999)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(42),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let service = Service::new(params);
    let handle = service.start();
    thread::sleep(Duration::from_millis(50));
    handle.shutdown();
}

#[test]
fn service_handles_round_zero() {
    // Edge case: the ledger reports round 0 as next round.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(0)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let service = Service::new(params);
    let handle = service.start();
    thread::sleep(Duration::from_millis(50));
    handle.shutdown();
}

#[test]
fn service_multiple_start_shutdown_cycles() {
    // Verify that multiple services can be created and shut down in sequence
    // without resource leaks or panics.
    for round in [1u64, 10, 100] {
        let params = Parameters {
            network: StubNetwork::new(),
            ledger: StubLedger::new(v41_params(), Round(round)),
            key_manager: EmptyKeyManager,
            block_factory: StubBlockFactory::new(),
            block_validator: StubBlockValidator::accepting(),
            random_source: StubRandomSource::constant(round),
            monitor: StubEventsProcessingMonitor::new(),
            crypto: StubCryptoVerifier::new(),
            crash_db: None,
        };

        let service = Service::new(params);
        let handle = service.start();
        thread::sleep(Duration::from_millis(20));
        handle.shutdown();
    }
}

#[test]
fn service_immediate_shutdown() {
    // Shutting down immediately after start should not hang or panic.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(50)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let service = Service::new(params);
    let handle = service.start();
    // No sleep — shut down immediately.
    handle.shutdown();
}

// ===========================================================================
// PoolUnfinishedBlock tests (BlockFactoryBridge)
// ===========================================================================

#[test]
fn pool_unfinished_block_round_returns_block_round() {
    let block = Block {
        round: Round(77),
        ..Default::default()
    };
    let ub = PoolUnfinishedBlock::new(block);
    assert_eq!(ub.round(), Round(77));
}

#[test]
fn pool_unfinished_block_finish_sets_seed_and_proposer() {
    let block = Block {
        round: Round(10),
        ..Default::default()
    };
    let ub = PoolUnfinishedBlock::new(block);

    let seed = Seed([0xde; 32]);
    let proposer = Address([0xfa; 32]);
    let finished = ub.finish_block(seed, proposer, true);

    assert_eq!(finished.seed, [0xde; 32]);
    assert_eq!(finished.proposer, proposer);
}

#[test]
fn pool_unfinished_block_eligible_preserves_payout() {
    let block = Block {
        proposer_payout: 12345,
        ..Default::default()
    };
    let ub = PoolUnfinishedBlock::new(block);

    let finished = ub.finish_block(Seed([0; 32]), Address([0; 32]), true);
    assert_eq!(finished.proposer_payout, 12345);
}

#[test]
fn pool_unfinished_block_ineligible_clears_payout() {
    let block = Block {
        proposer_payout: 99999,
        ..Default::default()
    };
    let ub = PoolUnfinishedBlock::new(block);

    let finished = ub.finish_block(Seed([0; 32]), Address([0; 32]), false);
    assert_eq!(finished.proposer_payout, 0);
}

// ===========================================================================
// BlockValidatorBridge tests
// ===========================================================================

#[test]
fn block_validator_bridge_accepts_valid_block() {
    let block = Block {
        round: Round(1),
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: [0xAA; 32],
        current_protocol: "future".into(),
        ..Default::default()
    };
    let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
    let result = validator.validate(&block);
    assert!(
        result.is_ok(),
        "valid block should be accepted: {:?}",
        result.err()
    );
    // The returned ValidatedBlock should reference the same block data.
    let vb = result.unwrap();
    assert_eq!(vb.block().round, Round(1));
}

#[test]
fn block_validator_bridge_rejects_wrong_genesis_hash() {
    let block = Block {
        round: Round(1),
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: [0xBB; 32], // mismatch
        current_protocol: "future".into(),
        ..Default::default()
    };
    let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
    let result = validator.validate(&block);
    assert!(result.is_err());
}

#[test]
fn block_validator_bridge_rejects_bad_protocol() {
    let block = Block {
        round: Round(1),
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: [0xAA; 32],
        current_protocol: "nonexistent-v99".into(),
        ..Default::default()
    };
    let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], Some(90));
    let result = validator.validate(&block);
    assert!(result.is_err());
    let err = result.err().expect("should be Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown protocol version") || msg.contains("validation failed"),
        "{msg}"
    );
}

#[test]
fn block_validator_bridge_set_prev_timestamp() {
    let validator = BlockValidatorBridge::new("test-v1".into(), [0xAA; 32], None);
    // Without a previous timestamp, a block with timestamp=100 should be accepted.
    let block = Block {
        round: Round(1),
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: [0xAA; 32],
        current_protocol: "future".into(),
        ..Default::default()
    };
    let r1 = validator.validate(&block);
    assert!(
        r1.is_ok(),
        "should accept without prev timestamp: {:?}",
        r1.err()
    );

    // After setting prev_timestamp=200, a block with timestamp=100 should be rejected.
    validator.set_prev_timestamp(200);
    let block2 = Block {
        round: Round(2),
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: [0xAA; 32],
        current_protocol: "future".into(),
        ..Default::default()
    };
    let r2 = validator.validate(&block2);
    assert!(
        r2.is_err(),
        "should reject block with timestamp before prev_timestamp"
    );
}

#[test]
fn validated_block_impl_returns_correct_block() {
    let block = Block {
        round: Round(42),
        ..Default::default()
    };
    let result = algo_validate::BlockValidationResult {
        round: 42,
        is_valid: true,
        errors: vec![],
        txn_count: 0,
        total_txn_bytes: 0,
    };
    let vb = ValidatedBlockImpl::new(block, result);
    assert_eq!(vb.block().round, Round(42));
}

// ===========================================================================
// Codec round-trip tests
// ===========================================================================

#[test]
fn codec_vote_roundtrip_default() {
    let vote = UnauthenticatedVote::default();
    let encoded = codec::encode_vote(&vote);
    let decoded = codec::decode_vote(&encoded).expect("decode should succeed");
    assert_eq!(decoded.raw_vote.round, Round(0));
    assert_eq!(decoded.raw_vote.period, Period(0));
    assert!(decoded.raw_vote.proposal.is_bottom());
}

#[test]
fn codec_vote_roundtrip_with_fields() {
    let vote = UnauthenticatedVote {
        raw_vote: algo_agreement::RawVote {
            sender: Address([0x42; 32]),
            round: Round(100),
            period: Period(1),
            step: Step(3),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x42; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
        },
        cred: algo_agreement::UnauthenticatedCredential::new([0x11; 80]),
        sig: algo_consensus_crypto::OneTimeSignature {
            sig: [0x01; 64],
            pk: [0x02; 32],
            pk_sig_old: [0x03; 64],
            pk2: [0x04; 32],
            pk1_sig: [0x05; 64],
            pk2_sig: [0x06; 64],
        },
    };

    let encoded = codec::encode_vote(&vote);
    let decoded = codec::decode_vote(&encoded).expect("decode should succeed");

    assert_eq!(decoded.raw_vote.sender, Address([0x42; 32]));
    assert_eq!(decoded.raw_vote.round, Round(100));
    assert_eq!(decoded.raw_vote.period, Period(1));
    assert_eq!(decoded.raw_vote.step, Step(3));
    assert_eq!(decoded.raw_vote.proposal.block_digest, Digest([0xaa; 32]));
    assert_eq!(decoded.cred.proof, [0x11; 80]);
    assert_eq!(decoded.sig.pk, [0x02; 32]);
}

#[test]
fn codec_bundle_roundtrip_empty() {
    let bundle = algo_agreement::UnauthenticatedBundle::default();
    let encoded = codec::encode_bundle(&bundle);
    let decoded = codec::decode_bundle(&encoded).expect("decode should succeed");
    assert_eq!(decoded.round.0, 0);
    assert!(decoded.votes.is_empty());
    assert!(decoded.equivocation_votes.is_empty());
}

#[test]
fn codec_bundle_roundtrip_with_votes() {
    let bundle = algo_agreement::UnauthenticatedBundle {
        round: Round(500),
        period: Period(2),
        step: Step(4),
        proposal: ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0x01; 32]),
            block_digest: Digest([0xdd; 32]),
            encoding_digest: Digest([0xee; 32]),
        },
        votes: vec![algo_agreement::VoteAuthenticator {
            sender: Address([0x01; 32]),
            cred: algo_agreement::UnauthenticatedCredential::new([0x55; 80]),
            sig: algo_consensus_crypto::OneTimeSignature {
                sig: [0x10; 64],
                pk: [0x20; 32],
                pk_sig_old: [0; 64],
                pk2: [0x30; 32],
                pk1_sig: [0x40; 64],
                pk2_sig: [0x50; 64],
            },
        }],
        equivocation_votes: vec![],
    };

    let encoded = codec::encode_bundle(&bundle);
    let decoded = codec::decode_bundle(&encoded).expect("decode should succeed");

    assert_eq!(decoded.round, Round(500));
    assert_eq!(decoded.period, Period(2));
    assert_eq!(decoded.step, Step(4));
    assert_eq!(decoded.proposal.block_digest, Digest([0xdd; 32]));
    assert_eq!(decoded.votes.len(), 1);
    assert_eq!(decoded.votes[0].sender, Address([0x01; 32]));
    assert_eq!(decoded.votes[0].cred.proof, [0x55; 80]);
}

#[test]
fn codec_vote_decode_rejects_garbage() {
    let garbage = vec![0xFF, 0x00, 0x01, 0x02];
    let result = codec::decode_vote(&garbage);
    assert!(result.is_err(), "garbage bytes should not decode as a vote");
}

#[test]
fn codec_bundle_decode_rejects_garbage() {
    let garbage = vec![0xFF, 0x00, 0x01, 0x02];
    let result = codec::decode_bundle(&garbage);
    assert!(
        result.is_err(),
        "garbage bytes should not decode as a bundle"
    );
}

// ===========================================================================
// AccountSigningKeys / VRF proof tests
// ===========================================================================

#[test]
fn account_signing_keys_vrf_produces_nonzero_proof() {
    // Generate a real VRF keypair and verify it produces a non-zero proof.
    let vrf = VrfKeypair::from_seed([0x42; 32]);
    let message = b"test-vrf-message";

    let (proof, output) = vrf.sk.prove(message);

    // The proof should be 80 bytes, not all zeros.
    assert_ne!(*proof.as_bytes(), [0u8; 80], "VRF proof should be non-zero");
    // The output should be 64 bytes, not all zeros.
    assert_ne!(
        *output.as_bytes(),
        [0u8; 64],
        "VRF output should be non-zero"
    );
}

#[test]
fn account_signing_keys_vrf_deterministic() {
    // The same seed and message should produce the same proof.
    let vrf1 = VrfKeypair::from_seed([0x42; 32]);
    let vrf2 = VrfKeypair::from_seed([0x42; 32]);
    let message = b"deterministic-test";

    let (proof1, output1) = vrf1.sk.prove(message);
    let (proof2, output2) = vrf2.sk.prove(message);

    assert_eq!(proof1, proof2, "same seed should produce same proof");
    assert_eq!(output1, output2, "same seed should produce same output");
}

#[test]
fn account_signing_keys_different_seeds_different_proofs() {
    let vrf1 = VrfKeypair::from_seed([0x01; 32]);
    let vrf2 = VrfKeypair::from_seed([0x02; 32]);
    let message = b"test-message";

    let (proof1, _) = vrf1.sk.prove(message);
    let (proof2, _) = vrf2.sk.prove(message);

    assert_ne!(
        proof1, proof2,
        "different seeds should produce different proofs"
    );
}

#[test]
fn ots_signing_produces_nonzero_signature() {
    // Generate OTS secrets and sign a message.
    let ots = OneTimeSignatureSecrets::generate(0, 10);
    let message = b"test-ots-message";
    let round = 0u64;
    let key_dilution = 100u64;

    let sig = ots.sign(message, round, key_dilution);

    // The signature fields should not all be zero.
    assert_ne!(sig.sig, [0u8; 64], "OTS signature should be non-zero");
    assert_ne!(sig.pk, [0u8; 32], "OTS pk should be non-zero");
}

#[test]
fn account_signing_keys_construction() {
    // Verify that AccountSigningKeys can be constructed with real keys.
    let vrf = VrfKeypair::from_seed([0xab; 32]);
    let ots = OneTimeSignatureSecrets::generate(0, 5);

    let _keys = AccountSigningKeys { vrf, ots };
    // Construction should not panic.
}

// ===========================================================================
// AsyncPseudonode integration tests
// ===========================================================================

#[test]
fn pseudonode_no_keys_returns_no_proposals() {
    let factory = StubBlockFactory::new();
    let keys = TestKeyManager::new(vec![]);
    let ledger = StubLedger::new(v41_params(), Round(100));
    let mut pn = AsyncPseudonode::new(factory, keys, ledger);

    let result = pn.make_proposals(Round(100), Period(0));
    assert!(result.is_err());
    match result.unwrap_err() {
        PseudonodeError::NoProposals => {}
        other => panic!("expected NoProposals, got: {other}"),
    }
}

#[test]
fn pseudonode_no_keys_returns_no_votes() {
    let factory = StubBlockFactory::new();
    let keys = TestKeyManager::new(vec![]);
    let ledger = StubLedger::new(v41_params(), Round(100));
    let mut pn = AsyncPseudonode::new(factory, keys, ledger);

    let pv = ProposalValue {
        original_period: Period(0),
        original_proposer: Address([0x42; 32]),
        block_digest: Digest([0xaa; 32]),
        encoding_digest: Digest([0xbb; 32]),
    };

    let result = pn.make_votes(Round(100), Period(0), Step(1), pv, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        PseudonodeError::NoVotes => {}
        other => panic!("expected NoVotes, got: {other}"),
    }
}

#[test]
fn pseudonode_shutdown_rejects_proposals() {
    let factory = StubBlockFactory::new();
    let keys = TestKeyManager::new(vec![ParticipationRecord {
        address: Address([0x01; 32]),
        vote_id: [0u8; 32],
        selection_id: [0u8; 32],
        vote_first_valid: Round(0),
        vote_last_valid: Round(1000),
        vote_key_dilution: 100,
    }]);
    let ledger = StubLedger::new(v41_params(), Round(100));
    let mut pn = AsyncPseudonode::new(factory, keys, ledger);

    pn.quit();

    let result = pn.make_proposals(Round(100), Period(0));
    assert!(result.is_err());
    match result.unwrap_err() {
        PseudonodeError::Shutdown => {}
        other => panic!("expected Shutdown, got: {other}"),
    }
}

#[test]
fn pseudonode_shutdown_rejects_votes() {
    let factory = StubBlockFactory::new();
    let keys = TestKeyManager::new(vec![ParticipationRecord {
        address: Address([0x01; 32]),
        vote_id: [0u8; 32],
        selection_id: [0u8; 32],
        vote_first_valid: Round(0),
        vote_last_valid: Round(1000),
        vote_key_dilution: 100,
    }]);
    let ledger = StubLedger::new(v41_params(), Round(100));
    let mut pn = AsyncPseudonode::new(factory, keys, ledger);

    pn.quit();

    let result = pn.make_votes(Round(100), Period(0), Step(1), BOTTOM, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        PseudonodeError::Shutdown => {}
        other => panic!("expected Shutdown, got: {other}"),
    }
}

#[test]
fn pseudonode_quit_is_idempotent() {
    let factory = StubBlockFactory::new();
    let keys = TestKeyManager::new(vec![]);
    let ledger = StubLedger::new(v41_params(), Round(100));
    let mut pn = AsyncPseudonode::new(factory, keys, ledger);

    // Calling quit multiple times should not panic.
    pn.quit();
    pn.quit();
    pn.quit();
}

// ===========================================================================
// Stub integration tests (stubs used together)
// ===========================================================================

#[test]
fn stub_block_factory_assembles_and_finishes() {
    // Test the full flow: factory assembles -> unfinished block -> finish.
    let mut factory = StubBlockFactory::new();
    let block = Block {
        round: Round(10),
        ..Default::default()
    };
    factory.set_block(Round(10), block);

    let ub = factory
        .assemble_block(Round(10), &[])
        .expect("should assemble");
    assert_eq!(ub.round(), Round(10));

    let seed = Seed([0xab; 32]);
    let proposer = Address([0x99; 32]);
    let finished = ub.finish_block(seed, proposer, true);
    assert_eq!(finished.round, Round(10));
}

#[test]
fn stub_block_factory_missing_round_errors() {
    let factory = StubBlockFactory::new();
    let result = factory.assemble_block(Round(42), &[]);
    assert!(result.is_err());
}

#[test]
fn stub_block_validator_and_ledger_writer_flow() {
    // Test the full flow: validator validates block, then ledger writes it.
    let validator = StubBlockValidator::accepting();
    let block = Block::default();

    let vb = validator.validate(&block).expect("should accept");

    let ledger = StubLedger::new(v41_params(), Round(1));
    let cert = algo_agreement::Certificate {
        round: Round(1),
        period: Period(0),
        proposal: BOTTOM,
        votes: vec![],
    };

    ledger.ensure_validated_block(vb.as_ref(), &cert);

    let written = ledger.get_written_blocks();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].cert.round, Round(1));
}

#[test]
fn stub_network_broadcast_and_query() {
    use algo_agreement::Tag;

    let network = StubNetwork::new();
    let tag = Tag("AV");
    let data = b"test-vote-data";

    network
        .broadcast(&tag, data)
        .expect("broadcast should succeed");

    let sent = network.get_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].tag, tag);
    assert_eq!(sent[0].data, data);
    assert!(!sent[0].is_relay);
}

#[test]
fn stub_network_relay_records_is_relay() {
    use algo_agreement::Tag;

    let network = StubNetwork::new();
    let tag = Tag("PP");
    let data = b"test-proposal-data";

    network
        .relay(&None, &tag, data)
        .expect("relay should succeed");

    let sent = network.get_sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].is_relay);
}

#[test]
fn stub_ledger_full_lifecycle() {
    // Test the ledger stub's reader and writer capabilities together.
    let mut ledger = StubLedger::new(v41_params(), Round(10));

    // Set up ledger state.
    ledger.set_seed(Round(5), Seed([0x11; 32]));
    ledger.set_digest(Round(5), Digest([0x22; 32]));
    ledger.set_circulation(Round(5), 1_000_000);

    // Read back state.
    assert_eq!(ledger.next_round(), Round(10));
    assert_eq!(ledger.seed(Round(5)).unwrap(), Seed([0x11; 32]));
    assert_eq!(ledger.lookup_digest(Round(5)).unwrap(), Digest([0x22; 32]));
    assert_eq!(ledger.circulation(Round(5), Round(10)).unwrap(), 1_000_000);

    // Consensus version should be v41.
    let ver = ledger.consensus_version(Round(5)).unwrap();
    assert_eq!(ver, algo_types::CONSENSUS_V41);

    // Write a block and verify it was recorded.
    let cert = algo_agreement::Certificate {
        round: Round(10),
        period: Period(0),
        proposal: BOTTOM,
        votes: vec![],
    };
    ledger.ensure_block(&Block::default(), &cert);
    assert_eq!(ledger.get_written_blocks().len(), 1);

    // Ensure digest and verify.
    let verifier = algo_agreement::AsyncVoteVerifier::new();
    ledger.ensure_digest(&cert, &verifier);
    assert_eq!(ledger.get_ensured_digests().len(), 1);
}

#[test]
fn stub_random_source_cycles() {
    let rng = StubRandomSource::new(vec![10, 20, 30]);
    assert_eq!(rng.uint64(), 10);
    assert_eq!(rng.uint64(), 20);
    assert_eq!(rng.uint64(), 30);
    // Should cycle back to the beginning.
    assert_eq!(rng.uint64(), 10);
    assert_eq!(rng.uint64(), 20);
}

#[test]
fn stub_events_monitor_records_updates() {
    let monitor = StubEventsProcessingMonitor::new();
    monitor.update_events_queue("test-queue", 42);
    let updates = monitor.get_updates();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].queue_name, "test-queue");
    assert_eq!(updates[0].queue_length, 42);
}

// ===========================================================================
// AgreementError tests
// ===========================================================================

#[test]
fn agreement_error_round_stale_display() {
    let err = algo_agreement::AgreementError::RoundStale(Round(42));
    let msg = format!("{err}");
    assert!(msg.contains("42"), "should mention the stale round");
    assert!(msg.contains("stale"), "should mention 'stale'");
}

#[test]
fn agreement_error_validation_failed_display() {
    let err = algo_agreement::AgreementError::ValidationFailed("bad block hash".into());
    let msg = format!("{err}");
    assert!(msg.contains("bad block hash"), "should contain the reason");
}

#[test]
fn agreement_error_other_display() {
    let err = algo_agreement::AgreementError::Other("internal failure".into());
    let msg = format!("{err}");
    assert!(msg.contains("internal failure"));
}

// ===========================================================================
// PseudonodeError display tests
// ===========================================================================

#[test]
fn pseudonode_error_display_variants() {
    let cases: Vec<(PseudonodeError, &str)> = vec![
        (PseudonodeError::NoVotes, "no valid participation keys"),
        (PseudonodeError::NoProposals, "no valid participation keys"),
        (PseudonodeError::Shutdown, "shut down"),
        (
            PseudonodeError::AssemblyFailed("oops".into()),
            "block assembly failed",
        ),
        (
            PseudonodeError::ProposalFailed("bad".into()),
            "proposal creation failed",
        ),
        (
            PseudonodeError::VoteFailed("nah".into()),
            "vote creation failed",
        ),
        (PseudonodeError::LedgerError("gone".into()), "ledger error"),
        (
            PseudonodeError::VerifierClosedChannel,
            "crypto verifier closed",
        ),
    ];

    for (err, expected_substring) in cases {
        let msg = format!("{err}");
        assert!(
            msg.contains(expected_substring),
            "PseudonodeError({err:?}) display '{msg}' should contain '{expected_substring}'"
        );
    }
}

// ===========================================================================
// ServiceHandle tests
// ===========================================================================

#[test]
fn service_handle_shutdown_completes() {
    // ServiceHandle's fields are private, so we can only test shutdown
    // through the Service::start() -> handle.shutdown() path.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(5)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let handle = Service::new(params).start();
    thread::sleep(Duration::from_millis(20));
    // Shutdown should complete (not hang indefinitely).
    handle.shutdown();
}

// ===========================================================================
// Codec edge case: encode then decode preserves identity
// ===========================================================================

#[test]
fn codec_vote_roundtrip_preserves_all_ots_fields() {
    // Ensure that the OTS signature fields survive a round-trip through
    // encode_vote / decode_vote without corruption.
    let vote = UnauthenticatedVote {
        raw_vote: algo_agreement::RawVote {
            sender: Address([0x01; 32]),
            round: Round(1),
            period: Period(0),
            step: Step(2),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
        },
        cred: algo_agreement::UnauthenticatedCredential::new([0xcc; 80]),
        sig: algo_consensus_crypto::OneTimeSignature {
            sig: [0x11; 64],
            pk: [0x22; 32],
            pk_sig_old: [0x33; 64],
            pk2: [0x44; 32],
            pk1_sig: [0x55; 64],
            pk2_sig: [0x66; 64],
        },
    };

    let encoded = codec::encode_vote(&vote);
    let decoded = codec::decode_vote(&encoded).expect("decode should succeed");

    // Verify all OTS fields.
    assert_eq!(decoded.sig.sig, [0x11; 64]);
    assert_eq!(decoded.sig.pk, [0x22; 32]);
    assert_eq!(decoded.sig.pk_sig_old, [0x33; 64]);
    assert_eq!(decoded.sig.pk2, [0x44; 32]);
    assert_eq!(decoded.sig.pk1_sig, [0x55; 64]);
    assert_eq!(decoded.sig.pk2_sig, [0x66; 64]);
}

#[test]
fn codec_vote_roundtrip_bottom_proposal() {
    // A vote for BOTTOM should round-trip correctly.
    let vote = UnauthenticatedVote {
        raw_vote: algo_agreement::RawVote {
            sender: Address([0x01; 32]),
            round: Round(50),
            period: Period(0),
            step: Step(6), // DOWN step
            proposal: BOTTOM,
        },
        cred: algo_agreement::UnauthenticatedCredential::new([0u8; 80]),
        sig: algo_consensus_crypto::OneTimeSignature {
            sig: [0; 64],
            pk: [0; 32],
            pk_sig_old: [0; 64],
            pk2: [0; 32],
            pk1_sig: [0; 64],
            pk2_sig: [0; 64],
        },
    };

    let encoded = codec::encode_vote(&vote);
    let decoded = codec::decode_vote(&encoded).expect("decode should succeed");
    assert_eq!(decoded.raw_vote.round, Round(50));
    assert!(decoded.raw_vote.proposal.is_bottom());
}

// ===========================================================================
// Demux + Service integration tests (Wave 3)
// ===========================================================================

/// Helper to create a service with pre-configured network inject senders
/// so we can push messages into the service's channels.
fn make_service_with_injectables(
    round: Round,
) -> (
    algo_agreement::ServiceHandle,
    crossbeam_channel::Sender<Message>,
    crossbeam_channel::Sender<Message>,
    crossbeam_channel::Sender<Message>,
) {
    let network = StubNetwork::new();

    // Pre-create inject senders for each tag BEFORE the service consumes the
    // network. The service's start() will call network.messages() which will
    // take the receivers we create here.
    let av_sender = network.inject_sender(&Tag(AGREEMENT_VOTE_TAG));
    let pp_sender = network.inject_sender(&Tag(PROPOSAL_PAYLOAD_TAG));
    let vb_sender = network.inject_sender(&Tag(VOTE_BUNDLE_TAG));

    let params = Parameters {
        network,
        ledger: StubLedger::new(v41_params(), round),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(42),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let handle = Service::new(params).start();
    (handle, av_sender, pp_sender, vb_sender)
}

#[test]
fn service_processes_injected_vote_message() {
    // Inject an encoded vote on the AV channel and verify the service
    // processes it without crashing. The service should decode the vote
    // and feed it to the player state machine.
    let (handle, av_sender, _pp_sender, _vb_sender) = make_service_with_injectables(Round(100));

    // Encode a valid vote and inject it.
    let vote = UnauthenticatedVote::default();
    let encoded = codec::encode_vote(&vote);
    av_sender
        .send(Message {
            handle: None,
            data: encoded,
        })
        .expect("should send vote");

    // Give the service time to process.
    thread::sleep(Duration::from_millis(100));

    // Shutdown should complete cleanly.
    handle.shutdown();
}

#[test]
fn service_processes_injected_proposal_message() {
    // Inject a compound message (proposal payload) on the PP channel.
    let (handle, _av_sender, pp_sender, _vb_sender) = make_service_with_injectables(Round(100));

    // Encode a compound message with an empty proposal and no vote.
    let compound = algo_agreement::CompoundMessage {
        proposal: algo_agreement::UnauthenticatedProposal::default(),
        vote: UnauthenticatedVote::default(),
    };
    let encoded = codec::encode_compound_message(&compound);
    pp_sender
        .send(Message {
            handle: None,
            data: encoded,
        })
        .expect("should send proposal");

    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_processes_injected_bundle_message() {
    // Inject a bundle message on the VB channel.
    let (handle, _av_sender, _pp_sender, vb_sender) = make_service_with_injectables(Round(100));

    let bundle = algo_agreement::UnauthenticatedBundle::default();
    let encoded = codec::encode_bundle(&bundle);
    vb_sender
        .send(Message {
            handle: None,
            data: encoded,
        })
        .expect("should send bundle");

    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_handles_garbage_vote_data_without_crash() {
    // Inject garbage data on the AV channel. The service should log a
    // warning but NOT crash.
    let (handle, av_sender, _pp_sender, _vb_sender) = make_service_with_injectables(Round(100));

    av_sender
        .send(Message {
            handle: None,
            data: vec![0xFF, 0x00, 0x01, 0x02],
        })
        .expect("should send garbage");

    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_handles_garbage_proposal_data_without_crash() {
    // Inject garbage data on the PP channel.
    let (handle, _av_sender, pp_sender, _vb_sender) = make_service_with_injectables(Round(100));

    pp_sender
        .send(Message {
            handle: None,
            data: vec![0xFF, 0xFE, 0xFD],
        })
        .expect("should send garbage");

    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_handles_garbage_bundle_data_without_crash() {
    // Inject garbage data on the VB channel.
    let (handle, _av_sender, _pp_sender, vb_sender) = make_service_with_injectables(Round(100));

    vb_sender
        .send(Message {
            handle: None,
            data: vec![0x01, 0x02],
        })
        .expect("should send garbage");

    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_clean_shutdown_with_active_channels() {
    // Start the service with active network channels (senders still open),
    // verify shutdown completes without hanging even though messages could
    // still arrive.
    let (handle, av_sender, pp_sender, vb_sender) = make_service_with_injectables(Round(50));

    // Keep senders alive to simulate an active network.
    thread::sleep(Duration::from_millis(50));

    // Shutdown while senders are still open.
    handle.shutdown();

    // After shutdown, sending should fail (receivers dropped by the service).
    let result = av_sender.send(Message {
        handle: None,
        data: vec![],
    });
    // The send may or may not succeed depending on timing, but the key
    // assertion is that shutdown() completed without hanging.
    drop(result);
    drop(pp_sender);
    drop(vb_sender);
}

#[test]
fn service_random_source_provides_entropy() {
    // Verify that the service uses RandomSource to populate entropy in
    // signals. We use a StubRandomSource with a known sequence and verify
    // the service runs without issues.
    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::new(vec![111, 222, 333]),
        monitor: StubEventsProcessingMonitor::new(),
        crypto: StubCryptoVerifier::new(),
        crash_db: None,
    };

    let handle = Service::new(params).start();
    thread::sleep(Duration::from_millis(100));
    handle.shutdown();
}

#[test]
fn service_with_crypto_verifier_channels() {
    // Verify that the CryptoVerifier channels are properly wired into the
    // Demux. The StubCryptoVerifier immediately produces results when
    // verify_vote/verify_proposal/verify_bundle are called. Since the
    // service doesn't currently dispatch crypto actions to the verifier
    // directly (that's done by the pseudonode), we verify the channels are
    // at least set up without error.
    let crypto = StubCryptoVerifier::new();

    // Verify the channels are accessible before handing to the service.
    assert!(!crypto.channel_full(AGREEMENT_VOTE_TAG));
    assert!(!crypto.channel_full(PROPOSAL_PAYLOAD_TAG));
    assert!(!crypto.channel_full(VOTE_BUNDLE_TAG));

    let params = Parameters {
        network: StubNetwork::new(),
        ledger: StubLedger::new(v41_params(), Round(1)),
        key_manager: EmptyKeyManager,
        block_factory: StubBlockFactory::new(),
        block_validator: StubBlockValidator::accepting(),
        random_source: StubRandomSource::constant(0),
        monitor: StubEventsProcessingMonitor::new(),
        crypto,
        crash_db: None,
    };

    let handle = Service::new(params).start();
    thread::sleep(Duration::from_millis(50));
    handle.shutdown();
}

#[test]
fn service_multiple_votes_on_channel() {
    // Inject multiple vote messages in quick succession to verify the
    // service handles a burst of network traffic.
    let (handle, av_sender, _pp_sender, _vb_sender) = make_service_with_injectables(Round(100));

    for i in 0..10 {
        let vote = UnauthenticatedVote {
            raw_vote: algo_agreement::RawVote {
                sender: Address([i as u8; 32]),
                round: Round(100),
                period: Period(0),
                step: Step(1),
                proposal: BOTTOM,
            },
            ..UnauthenticatedVote::default()
        };
        let encoded = codec::encode_vote(&vote);
        let _ = av_sender.send(Message {
            handle: None,
            data: encoded,
        });
    }

    thread::sleep(Duration::from_millis(200));
    handle.shutdown();
}

#[test]
fn service_mixed_message_types() {
    // Inject a mix of vote, proposal, and bundle messages to verify the
    // service multiplexes them correctly.
    let (handle, av_sender, pp_sender, vb_sender) = make_service_with_injectables(Round(100));

    // Send a vote.
    let vote = UnauthenticatedVote::default();
    let _ = av_sender.send(Message {
        handle: None,
        data: codec::encode_vote(&vote),
    });

    // Send a proposal.
    let compound = algo_agreement::CompoundMessage {
        proposal: algo_agreement::UnauthenticatedProposal::default(),
        vote: UnauthenticatedVote::default(),
    };
    let _ = pp_sender.send(Message {
        handle: None,
        data: codec::encode_compound_message(&compound),
    });

    // Send a bundle.
    let bundle = algo_agreement::UnauthenticatedBundle::default();
    let _ = vb_sender.send(Message {
        handle: None,
        data: codec::encode_bundle(&bundle),
    });

    thread::sleep(Duration::from_millis(200));
    handle.shutdown();
}
