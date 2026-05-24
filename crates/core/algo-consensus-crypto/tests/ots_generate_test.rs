//! Writer-side parity tests for `OneTimeSignatureSecrets::generate` /
//! `generate_with_rng`.
//!
//! Mirrors `../go-algorand/crypto/onetimesig.go::GenerateOneTimeSignatureSecrets`
//! and `…RNG`. The sign / verify / persist round-trip is the canonical
//! conformance check — we already produce identical canonical msgpack to
//! Go's `OneTimeSignatureSecretsPersistent` (see inline `onetimesig::tests`
//! and the Phase B reader fixtures), so a generate → encode → decode →
//! sign → verify chain here is end-to-end evidence that the writer-side
//! API is sound.
//!
//! Byte-for-byte parity with a Go `crypto.PRNG`-seeded run would require
//! HMAC-DRBG; that is deferred to the Phase C fixture capture task
//! ([[TASK-182]]).

use algo_consensus_crypto::onetimesig::{verify_one_time_signature, OneTimeSignatureSecrets};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;

#[test]
fn generate_produces_unique_verifiers_over_100_iterations() {
    // Each call must draw a fresh master keypair from the OS RNG.
    let mut verifiers: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..100 {
        let secrets = OneTimeSignatureSecrets::generate(0, 4);
        assert!(
            verifiers.insert(secrets.verifier()),
            "iteration {i}: duplicate master verifier — RNG is broken"
        );
    }
}

#[test]
fn generate_batch_count_matches_request() {
    for n in [0u64, 1, 5, 32] {
        let secrets = OneTimeSignatureSecrets::generate(7, n);
        assert_eq!(
            secrets.num_batches() as u64,
            n,
            "generate({n}) should produce exactly {n} batch subkeys"
        );
        assert_eq!(
            secrets.first_batch(),
            7,
            "first_batch must equal start_batch"
        );
        assert_eq!(secrets.num_offsets(), 0, "no offsets generated up front");
    }
}

#[test]
fn generate_with_rng_is_deterministic_for_a_fixed_seed() {
    let seed: u64 = 0xA1B2_C3D4_E5F6_0789;

    let mut rng_a = ChaCha20Rng::seed_from_u64(seed);
    let mut rng_b = ChaCha20Rng::seed_from_u64(seed);

    let s_a = OneTimeSignatureSecrets::generate_with_rng(10, 6, &mut rng_a);
    let s_b = OneTimeSignatureSecrets::generate_with_rng(10, 6, &mut rng_b);

    // Master verifier must match.
    assert_eq!(
        s_a.verifier(),
        s_b.verifier(),
        "verifier must be deterministic"
    );

    // Encoded forms must match byte-for-byte, which transitively proves every
    // batch subkey's PK / SK / sig2 also match.
    assert_eq!(
        s_a.to_msgpack(),
        s_b.to_msgpack(),
        "deterministic RNG must yield identical canonical msgpack encoding"
    );
}

#[test]
fn generate_then_sign_then_verify_roundtrip() {
    // Pre-generated batch subkeys, fresh offset key minted per sign().
    let key_dilution = 16u64;
    let secrets = OneTimeSignatureSecrets::generate(0, 4);
    let verifier = secrets.verifier();

    for round in 0..(4 * key_dilution) {
        let msg = format!("msg-{round}");
        let sig = secrets.sign(msg.as_bytes(), round, key_dilution);

        let batch = round / key_dilution;
        let offset = round % key_dilution;
        assert!(
            verify_one_time_signature(&sig, &verifier, batch, offset, msg.as_bytes()),
            "generated secrets must sign a signature that verifies under their own verifier (round {round})"
        );
    }
}

#[test]
fn generate_then_encode_then_decode_roundtrip() {
    // Capture: a generated tree → its canonical msgpack → restored secrets.
    // The restored copy must produce the same verifier and the same encoding.
    let secrets = OneTimeSignatureSecrets::generate(3, 5);
    let encoded = secrets.to_msgpack();

    let restored = OneTimeSignatureSecrets::from_msgpack(&encoded)
        .expect("encode → decode round-trip must succeed");

    assert!(
        restored.is_restored(),
        "decoded secrets must be marked restored"
    );
    assert_eq!(
        restored.verifier(),
        secrets.verifier(),
        "verifier must survive encode/decode"
    );
    assert_eq!(restored.first_batch(), secrets.first_batch());
    assert_eq!(restored.num_batches(), secrets.num_batches());

    // Re-encode and compare byte-for-byte: this is the strongest possible
    // structural equality check short of an explicit field-by-field compare.
    assert_eq!(
        restored.to_msgpack(),
        encoded,
        "re-encoded restored secrets must equal the original encoding"
    );
}

#[test]
fn generate_with_rng_and_generate_share_signing_semantics() {
    // The RNG-injected variant must produce a tree that signs and verifies
    // identically to one produced by the system-RNG path.
    let key_dilution = 8u64;
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let secrets = OneTimeSignatureSecrets::generate_with_rng(0, 3, &mut rng);
    let verifier = secrets.verifier();

    for round in 0..(3 * key_dilution) {
        let msg = format!("rng-msg-{round}");
        let sig = secrets.sign(msg.as_bytes(), round, key_dilution);
        let batch = round / key_dilution;
        let offset = round % key_dilution;
        assert!(
            verify_one_time_signature(&sig, &verifier, batch, offset, msg.as_bytes()),
            "RNG-generated secrets must verify (round {round})"
        );
    }
}
