//! Byte-equal parity vs go-algorand `crypto/multisig.go` (v4.5.1-stable).
//!
//! Fixtures were captured by running `crypto.MultisigAddrGen` with
//! ed25519 public keys derived deterministically from
//! `crypto.GenerateSignatureSecrets(sha256(label))`. The same fixtures
//! anchor `algokey-rust multisig` byte-equality in Phase B's
//! cross-impl tests (TASK-171).

use algo_consensus_crypto::{multisig_addr_gen, multisig_assemble, multisig_sign};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};

/// Derive the same ed25519 keypair Go produces from
/// `crypto.GenerateSignatureSecrets(sha256(label))`.
fn signer_from_label(label: &str) -> (SigningKey, [u8; 32]) {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

/// Each fixture: `(threshold, signer labels, expected address hex)`.
const FIXTURES: &[(u8, &[&str], &str)] = &[
    (
        2,
        &["alpha", "bravo", "charlie"],
        "2d3a96e11824cda423452862bc31004b0cb31cb0b8fdfcf4e8499a08acbb353b",
    ),
    (
        3,
        &["delta", "echo", "foxtrot"],
        "bbcf0a79449a9409f855dbb512a145f68afcc62c6ed72ff2ce16b11e19357414",
    ),
    (
        1,
        &["golf", "hotel", "india", "juliet", "kilo"],
        "c3c9456574ed874ea6398ff227a365c183d5115bfbf83651c63597beb18d290c",
    ),
    (
        1,
        &["lima", "mike"],
        "c562ebcba6d9242c68c2a266baded24301b993367149e908f9c280efd2060920",
    ),
    (
        2,
        &["november", "oscar"],
        "396f2b58f15bb20546f898d084f98321fa11c616744aa4410b8e4c9210e96af7",
    ),
];

#[test]
fn addr_gen_byte_equal_to_go_for_all_fixtures() {
    for (threshold, labels, expected_hex) in FIXTURES {
        let pks: Vec<[u8; 32]> = labels.iter().map(|l| signer_from_label(l).1).collect();
        let addr = multisig_addr_gen(1, *threshold, &pks).expect("addr gen");
        let got = hex::encode(addr.0);
        assert_eq!(
            &got, expected_hex,
            "addr divergence for threshold={threshold} labels={labels:?}"
        );
    }
}

/// Sign-then-assemble round trip: produce per-signer partials, assemble,
/// then verify each subsig under ed25519 directly. We don't pull
/// `algo-validate` in here (would create a dep cycle); the higher-level
/// cross-impl test in `algokey-rust` does the full verify path.
#[test]
fn sign_and_assemble_round_trip_under_threshold_signers() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let labels = &FIXTURES[0].1; // 2-of-3 alpha/bravo/charlie
    let threshold = FIXTURES[0].0;
    let signers: Vec<_> = labels.iter().map(|l| signer_from_label(l)).collect();
    let pks: Vec<[u8; 32]> = signers.iter().map(|(_, pk)| *pk).collect();
    let msg = b"hello, multisig";

    // Sign with the first `threshold` keys.
    let mut partials = Vec::new();
    for (sk, _) in signers.iter().take(threshold as usize) {
        partials.push(multisig_sign(msg, 1, threshold, &pks, sk).expect("sign"));
    }
    let combined = multisig_assemble(&partials).expect("assemble");
    assert_eq!(combined.threshold, threshold);
    assert_eq!(combined.subsigs.len(), pks.len());

    // First two subsigs filled, last is blank.
    for (i, sub) in combined.subsigs.iter().enumerate() {
        if i < threshold as usize {
            let sig = Signature::from_bytes(&sub.signature);
            let vk = VerifyingKey::from_bytes(&sub.public_key).expect("vk");
            vk.verify(msg, &sig).expect("ed25519 verify");
        } else {
            assert_eq!(
                sub.signature, [0u8; 64],
                "extra signer subsig must be blank"
            );
        }
    }
}
