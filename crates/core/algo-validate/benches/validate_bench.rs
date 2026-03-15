//! Criterion microbenchmarks for algo-validate.
//!
//! Benchmarks cover the hot paths in stateless block validation:
//!   - SHA-512/256 digest computation (block-sized and transaction-sized data)
//!   - ed25519 signature verification
//!   - Merkle tree root computation
//!   - Vector commitment computation (SHA-256 and SHA-512)
//!   - Full block validation (empty and with transactions)

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use algo_codec::canonical_encode_transaction;
use algo_types::{Address, Block, Round, SignedTransaction, Transaction};
use algo_validate::merkle::{compute_payset_merkle_root, compute_vector_commitment, HashAlgo};
use ed25519_dalek::{Signer, SigningKey};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha512_256};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_genesis_hash() -> [u8; 32] {
    [0xAA; 32]
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// Build a minimal valid block with the given payset.
fn make_block(payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(1),
        branch: ByteBuf::from(vec![0u8; 32]),
        seed: ByteBuf::from(vec![0u8; 32]),
        txn_commitment: ByteBuf::new(),
        timestamp: 100,
        genesis_id: "bench-v1".into(),
        genesis_hash: ByteBuf::from(test_genesis_hash().to_vec()),
        proposer: Address::default(),
        fee_sink: Address::default(),
        rewards_pool: Address::default(),
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: "future".into(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: ByteBuf::new(),
        txn256: ByteBuf::new(),
        txn512: ByteBuf::new(),
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        payset,
    }
}

/// Create a properly signed transaction ready for block inclusion.
///
/// The returned `SignedTransaction` has genesis fields stripped (as stored
/// in-block) with `has_genesis_id = true`.
fn make_signed_txn(key: &SigningKey, amount: u64) -> SignedTransaction {
    let pk = key.verifying_key();
    let sender = Address(pk.to_bytes());
    let txn = Transaction {
        txn_type: "pay".into(),
        sender,
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(1000),
        amount,
        receiver: Address([2u8; 32]),
        genesis_id: "bench-v1".into(),
        genesis_hash: ByteBuf::from(test_genesis_hash().to_vec()),
        ..Default::default()
    };

    // Sign: "TX" || canonical_encode(txn)
    let canonical = canonical_encode_transaction(&txn);
    let mut msg = Vec::with_capacity(2 + canonical.len());
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical);
    let sig = key.sign(&msg);

    // Strip genesis fields (as stored in-block).
    let mut stripped_txn = txn;
    stripped_txn.genesis_id = String::new();
    stripped_txn.genesis_hash = ByteBuf::new();

    SignedTransaction {
        txn: stripped_txn,
        sig: ByteBuf::from(sig.to_bytes().to_vec()),
        msig: None,
        lsig: None,
        auth_addr: None,
        has_genesis_id: true,
        has_genesis_hash: true,
        closing_amount: 0,
        asset_closing_amount: 0,
        sender_rewards: 0,
        receiver_rewards: 0,
        close_rewards: 0,
        eval_delta: None,
        apply_data_config_asset: 0,
        apply_data_application_id: 0,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// SHA-512/256 digest on data sizes representative of Algorand usage.
fn bench_sha512_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512_256");

    // ~200 bytes: typical single-transaction canonical encoding.
    let data_200 = vec![0xABu8; 200];
    group.bench_function("200B_txn_sized", |b| {
        b.iter(|| {
            let mut h = Sha512_256::new();
            h.update(black_box(&data_200));
            h.finalize()
        })
    });

    // ~1 KB: typical small block header or a few encoded transactions.
    let data_1k = vec![0xCDu8; 1024];
    group.bench_function("1KB_block_sized", |b| {
        b.iter(|| {
            let mut h = Sha512_256::new();
            h.update(black_box(&data_1k));
            h.finalize()
        })
    });

    // ~5 KB: medium block with several transactions.
    let data_5k = vec![0xEFu8; 5 * 1024];
    group.bench_function("5KB_medium_block", |b| {
        b.iter(|| {
            let mut h = Sha512_256::new();
            h.update(black_box(&data_5k));
            h.finalize()
        })
    });

    group.finish();
}

/// ed25519 signature verification — the dominant cost in block validation.
fn bench_ed25519_verify(c: &mut Criterion) {
    let key = test_signing_key();
    let stx = make_signed_txn(&key, 5000);

    // Restore genesis fields so verify_single_sig can compute the correct message.
    let mut stx_restored = stx.clone();
    stx_restored.txn.genesis_id = "bench-v1".into();
    stx_restored.txn.genesis_hash = ByteBuf::from(test_genesis_hash().to_vec());

    c.bench_function("ed25519_verify_single_sig", |b| {
        b.iter(|| {
            algo_validate::verify_single_sig(black_box(&stx_restored)).unwrap();
        })
    });
}

/// Merkle tree root computation over varying payset sizes.
fn bench_merkle_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_root");
    let key = test_signing_key();

    for &n in &[1, 4, 16, 64] {
        let payset: Vec<_> = (0..n).map(|i| make_signed_txn(&key, 1000 + i)).collect();
        let block = make_block(payset);

        group.bench_function(format!("{n}_txns"), |b| {
            b.iter(|| compute_payset_merkle_root(black_box(&block)))
        });
    }

    group.finish();
}

/// Vector commitment computation (SHA-256 and SHA-512 variants).
fn bench_vector_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("vector_commitment");
    let key = test_signing_key();

    // 16 transactions — a common atomic group size limit.
    let payset: Vec<_> = (0..16).map(|i| make_signed_txn(&key, 1000 + i)).collect();
    let block = make_block(payset);

    group.bench_function("sha256_16_txns", |b| {
        b.iter(|| compute_vector_commitment(black_box(&block), HashAlgo::Sha256))
    });

    group.bench_function("sha512_16_txns", |b| {
        b.iter(|| compute_vector_commitment(black_box(&block), HashAlgo::Sha512))
    });

    group.finish();
}

/// Full block validation (the top-level `validate_block` function).
fn bench_validate_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_block");
    let key = test_signing_key();
    let gh = test_genesis_hash();

    // Empty block — measures overhead of protocol checks, timestamp, commitment.
    let empty = make_block(vec![]);
    group.bench_function("empty_block", |b| {
        b.iter(|| algo_validate::validate_block(black_box(&empty), Some(90), "bench-v1", &gh, None))
    });

    // Block with 4 signed transactions — includes signature verification.
    let payset: Vec<_> = (0..4).map(|i| make_signed_txn(&key, 1000 + i)).collect();
    let mut block4 = make_block(payset);
    // Compute the correct Merkle commitment so the block validates cleanly.
    let root = compute_payset_merkle_root(&block4);
    block4.txn_commitment = ByteBuf::from(root.to_vec());

    group.bench_function("4_txn_block", |b| {
        b.iter(|| {
            algo_validate::validate_block(black_box(&block4), Some(90), "bench-v1", &gh, None)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sha512_256,
    bench_ed25519_verify,
    bench_merkle_root,
    bench_vector_commitment,
    bench_validate_block,
);
criterion_main!(benches);
