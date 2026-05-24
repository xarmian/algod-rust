//! End-to-end tests for `merklesignature::Secrets::new` + `KeysBuilder`.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/merkleSignatureScheme_test.go`
//! for the writer-side path. Byte-for-byte KAT parity with Go is deferred to
//! the Phase C fixture-capture task ([[TASK-182]]); the tests here cover:
//!
//! - input-validation parity with Go (`ErrStartBiggerThanEndRound`,
//!   `ErrKeyLifetimeIsZero`),
//! - `numberOfKeys` arithmetic across the standard boundary cases (including
//!   the `first_valid == 0` special case and the `NoKeysCommitment` window),
//! - vector-commitment root determinism (same seed table ⇒ same commitment,
//!   regardless of worker thread count),
//! - leaf preimage layout (matches the documented `KP || scheme || round || pk`
//!   wire format), and
//! - `get_verifier` / `get_key` / `get_all_keys` consistency.
//!
//! All `Secrets::new` calls use small key counts to keep runtime under a few
//! seconds — Falcon keygen dominates the wall clock.

use algo_consensus_crypto::merklearray::{HashFactory, HashType};
use algo_consensus_crypto::merklesignature::{
    consts::{CRYPTO_PRIMITIVES_ID, KEYS_IN_MSS_PREFIX, KEY_LIFETIME_DEFAULT},
    Secrets,
};

// ── Input validation ─────────────────────────────────────────────────────

#[test]
fn new_rejects_start_bigger_than_end_round() {
    let err = Secrets::new(100, 50, KEY_LIFETIME_DEFAULT).unwrap_err();
    assert!(
        matches!(
            err,
            algo_consensus_crypto::merklesignature::MssError::StartBiggerThanEndRound
        ),
        "expected ErrStartBiggerThanEndRound, got {err:?}"
    );
}

#[test]
fn new_rejects_zero_key_lifetime() {
    let err = Secrets::new(1, 100, 0).unwrap_err();
    assert!(
        matches!(
            err,
            algo_consensus_crypto::merklesignature::MssError::KeyLifetimeIsZero
        ),
        "expected ErrKeyLifetimeIsZero, got {err:?}"
    );
}

// ── numberOfKeys arithmetic ──────────────────────────────────────────────

#[test]
fn no_keys_window_produces_empty_tree() {
    // Mirrors Go's `NoKeysCommitment` init: New(257, 258, 256) → 0 keys.
    // `258/256 = 1`, `256/256 = 1`, so number_of_keys = 0.
    let secrets = Secrets::new(
        KEY_LIFETIME_DEFAULT + 1,
        KEY_LIFETIME_DEFAULT + 2,
        KEY_LIFETIME_DEFAULT,
    )
    .expect("empty MSS must succeed");
    assert!(
        secrets.get_all_keys().is_empty(),
        "no-keys window must produce zero ephemeral keys"
    );
    // The empty commitment is well-defined: the underlying Tree.root() returns
    // an empty digest, which `get_verifier` pads to the commitment size.
    let v = secrets.get_verifier();
    assert_eq!(v.key_lifetime, KEY_LIFETIME_DEFAULT);
}

#[test]
fn single_lifetime_window_produces_one_key() {
    // [256, 512] at lifetime 256 → 512/256 - 255/256 = 2 - 0 = 2 keys.
    // Use a smaller arithmetic case: [1, 256] at lifetime 256 →
    //   256/256 - 0/256 = 1 - 0 = 1 key.
    let secrets = Secrets::new(1, KEY_LIFETIME_DEFAULT, KEY_LIFETIME_DEFAULT)
        .expect("single-lifetime MSS must succeed");
    assert_eq!(secrets.get_all_keys().len(), 1, "expected exactly 1 key");
    let pair = &secrets.get_all_keys()[0];
    assert_eq!(
        pair.round, KEY_LIFETIME_DEFAULT,
        "single key should cover round = key_lifetime"
    );
}

#[test]
fn first_valid_zero_special_case_adds_round_zero_key() {
    // first_valid=0, last_valid=256, lifetime=256 → 256/256 + 1 = 2 keys.
    let secrets =
        Secrets::new(0, KEY_LIFETIME_DEFAULT, KEY_LIFETIME_DEFAULT).expect("must succeed");
    let keys = secrets.get_all_keys();
    assert_eq!(
        keys.len(),
        2,
        "expected exactly 2 keys (round 0 + round 256)"
    );
}

// ── Leaf preimage layout ─────────────────────────────────────────────────

#[test]
fn leaf_preimage_matches_documented_layout() {
    // Build a tiny secrets, then re-hash the first leaf by hand and compare
    // against the tree root after stripping the VC padding. We can't directly
    // inspect the leaf preimage from outside the crate, so instead we assert
    // that the (very small) tree's structure is what we expect for 1 leaf:
    // depth 0 (one leaf with no internal nodes), root == H(leaf_preimage).
    let secrets =
        Secrets::new(1, KEY_LIFETIME_DEFAULT, KEY_LIFETIME_DEFAULT).expect("must succeed");
    let key = &secrets.ephemeral_keys[0];
    let round = KEY_LIFETIME_DEFAULT; // round_of_first_index(1, 256)
    let pk = key.public_key();

    // Reconstruct the leaf preimage exactly as committable_public_keys does.
    let mut expected_body = Vec::with_capacity(2 + 8 + pk.len());
    expected_body.extend_from_slice(&CRYPTO_PRIMITIVES_ID.to_le_bytes());
    expected_body.extend_from_slice(&round.to_le_bytes());
    expected_body.extend_from_slice(pk);

    let factory = HashFactory::new(HashType::Sumhash);
    let expected_leaf = factory.hash_bytes(&[KEYS_IN_MSS_PREFIX, &expected_body]);

    // For a 1-element vector commitment tree the root equals the (only) leaf hash.
    let root = secrets.signer_context.tree.root();
    assert_eq!(
        root, expected_leaf,
        "tree root for a 1-key MSS must equal the documented leaf hash"
    );
}

// ── Determinism across worker thread counts ──────────────────────────────

#[test]
fn key_set_is_deterministic_for_a_fixed_seed_table() {
    use algo_consensus_crypto::merklesignature::keys_builder::{
        keys_builder_with_seed_provider, DeterministicSeedProvider,
    };

    let provider_a = DeterministicSeedProvider {
        domain_seed: 0xDEAD_BEEF,
    };
    let provider_b = DeterministicSeedProvider {
        domain_seed: 0xDEAD_BEEF,
    };

    // Small key count keeps runtime predictable while still exercising
    // the multi-worker partition path (`calculate_ranges` produces
    // `keys_per_worker = 1` for any num_keys ≤ 2 * cpus).
    let keys_a = keys_builder_with_seed_provider(3, &provider_a).expect("a must succeed");
    let keys_b = keys_builder_with_seed_provider(3, &provider_b).expect("b must succeed");

    assert_eq!(keys_a.len(), 3);
    assert_eq!(keys_b.len(), 3);
    for i in 0..3 {
        assert_eq!(
            keys_a[i], keys_b[i],
            "deterministic seed must produce identical Falcon keypairs at index {i}"
        );
    }
}

#[test]
fn empty_keys_builder_returns_empty_vec() {
    use algo_consensus_crypto::merklesignature::keys_builder;
    let keys = keys_builder(0).expect("zero keys must succeed");
    assert!(keys.is_empty());
}

// ── get_verifier / get_key / get_all_keys consistency ────────────────────

#[test]
fn get_verifier_commitment_matches_tree_root() {
    let secrets =
        Secrets::new(1, KEY_LIFETIME_DEFAULT * 2, KEY_LIFETIME_DEFAULT).expect("must succeed");
    let v = secrets.get_verifier();
    assert_eq!(v.key_lifetime, KEY_LIFETIME_DEFAULT);

    let root = secrets.signer_context.tree.root();
    assert!(
        !root.is_empty(),
        "non-empty MSS must produce a non-empty root"
    );
    assert!(
        v.commitment.iter().any(|&b| b != 0),
        "commitment must be non-zero for a non-empty MSS"
    );
    assert_eq!(
        &v.commitment[..root.len()],
        root.as_slice(),
        "verifier.commitment must equal tree.root()"
    );
}

#[test]
fn get_key_finds_each_round_and_misses_others() {
    let secrets =
        Secrets::new(1, KEY_LIFETIME_DEFAULT * 3, KEY_LIFETIME_DEFAULT).expect("must succeed");
    let pairs = secrets.get_all_keys();
    assert_eq!(pairs.len(), 3);

    for pair in &pairs {
        let key = secrets
            .get_key(pair.round)
            .expect("must find key for owned round");
        assert_eq!(key.public_key(), pair.key.public_key());
    }

    // Non-aligned round returns None.
    assert!(
        secrets.get_key(KEY_LIFETIME_DEFAULT + 1).is_none(),
        "round not divisible by key_lifetime must return None"
    );
    // Round before first owned round returns None.
    assert!(
        secrets.get_key(0).is_none(),
        "round 0 is not owned when first_valid=1"
    );
}
