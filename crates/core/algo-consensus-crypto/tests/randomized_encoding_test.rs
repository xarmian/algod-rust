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

//! Randomized msgpack round-trip encoding tests for the hand-rolled codecs
//! in `merklearray` and `merklesig`.
//!
//! Mirrors go-algorand's `TestRandomizedEncodingX` family
//! (`crypto/msgp_gen_test.go`, `crypto/merklearray/msgp_gen_test.go`,
//! `crypto/merklesignature/msgp_gen_test.go`), each of which is a thin
//! `protocol.RunEncodingTest(t, &SomeType{})` call. `RunEncodingTest`
//! (`protocol/codec_tester.go`) generates 1000 instances of the type with
//! reflection-randomized field values, msgpack round-trips each, and asserts
//! equality.
//!
//! algod-rust's `merklearray`/`merklesig` codecs are hand-written (not
//! reflection/derive-generated), so there is no generic reflection-based
//! fuzzer to reuse. Instead, [`assert_randomized_roundtrip`] is the one
//! shared driver — matching go's 1000-iteration loop — and each type below
//! supplies its own small random-instance generator plus its own
//! encode/decode functions. This closes Phase 17 issue #826 theme 3: the
//! existing round-trip tests for these types used fixed, hand-picked field
//! values, which won't surface a field that fails to round-trip only for
//! certain values (e.g. a boundary length, a field ordering that only
//! manifests for particular byte patterns).

use algo_consensus_crypto::merklearray::{
    GenericDigest, HashFactory, HashType, Proof, SingleLeafProof, Tree, MAX_HASH_DIGEST_SIZE,
};
use algo_consensus_crypto::merklesig::{
    decode_state_proof_keys, FalconSigner, FalconVerifier, Secrets, Signature, SignerContext,
    Verifier, MERKLE_SIGNATURE_SCHEME_ROOT_SIZE,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fmt::Debug;

/// Number of randomized iterations per type, matching go's
/// `protocol.RunEncodingTest` (`protocol/codec_tester.go`), which runs the
/// generate/encode/decode/compare cycle 1000 times per type.
const ITERATIONS: usize = 1000;

/// Shared randomized round-trip driver: generate `ITERATIONS` random
/// instances of `T` via `gen`, msgpack-encode each with `encode`, decode
/// with `decode`, and assert the decoded value equals the original.
///
/// `seed` is a fixed, per-call constant so a failure reproduces
/// deterministically across CI runs (no OS-randomness dependency).
fn assert_randomized_roundtrip<T: PartialEq + Debug>(
    seed: u64,
    mut gen: impl FnMut(&mut ChaCha20Rng) -> T,
    encode: impl Fn(&T) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> T,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    for i in 0..ITERATIONS {
        let original = gen(&mut rng);
        let encoded = encode(&original);
        let decoded = decode(&encoded);
        assert_eq!(
            decoded, original,
            "randomized msgpack round-trip mismatch at iteration {i} (seed {seed:#x})"
        );
    }
}

// ── Random-instance generators ──────────────────────────────────────────

fn gen_hash_type(rng: &mut ChaCha20Rng) -> HashType {
    match rng.gen_range(0..4) {
        0 => HashType::Sha512_256,
        1 => HashType::Sumhash,
        2 => HashType::Sha256,
        _ => HashType::Sha512,
    }
}

fn gen_hash_factory(rng: &mut ChaCha20Rng) -> HashFactory {
    HashFactory::new(gen_hash_type(rng))
}

fn gen_digest(rng: &mut ChaCha20Rng) -> GenericDigest {
    // Bounded well under MAX_HASH_DIGEST_SIZE — this exercises the codec's
    // variable-length bin/nil handling, not the allocation-bound rejection
    // path (that's covered separately by the DecodeBoundExceeded tests).
    let len = rng.gen_range(0..=MAX_HASH_DIGEST_SIZE.min(64));
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

fn gen_proof(rng: &mut ChaCha20Rng) -> Proof {
    let path_len = rng.gen_range(0..=6);
    let path = (0..path_len).map(|_| gen_digest(rng)).collect();
    Proof {
        path,
        hash_factory: gen_hash_factory(rng),
        tree_depth: rng.gen::<u8>(),
    }
}

fn gen_single_leaf_proof(rng: &mut ChaCha20Rng) -> SingleLeafProof {
    SingleLeafProof {
        proof: gen_proof(rng),
    }
}

fn gen_tree(rng: &mut ChaCha20Rng) -> Tree {
    let num_layers = rng.gen_range(0..=3);
    let levels = (0..num_layers)
        .map(|_| {
            let layer_len = rng.gen_range(0..=4);
            (0..layer_len).map(|_| gen_digest(rng)).collect()
        })
        .collect();
    Tree {
        levels,
        num_of_elements: rng.gen::<u64>(),
        hash: gen_hash_factory(rng),
        is_vector_commitment: rng.gen::<bool>(),
    }
}

fn gen_falcon_signer(rng: &mut ChaCha20Rng) -> FalconSigner {
    let mut signer = FalconSigner::default();
    rng.fill_bytes(&mut signer.pk);
    rng.fill_bytes(&mut signer.sk);
    signer
}

fn gen_falcon_verifier(rng: &mut ChaCha20Rng) -> FalconVerifier {
    let mut verifier = FalconVerifier::default();
    rng.fill_bytes(&mut verifier.k);
    verifier
}

fn gen_verifier(rng: &mut ChaCha20Rng) -> Verifier {
    let mut commitment = [0u8; MERKLE_SIGNATURE_SCHEME_ROOT_SIZE];
    rng.fill_bytes(&mut commitment);
    Verifier {
        commitment,
        key_lifetime: rng.gen::<u64>(),
    }
}

fn gen_signature(rng: &mut ChaCha20Rng) -> Signature {
    let sig_len = rng.gen_range(0..=64);
    let mut signature = vec![0u8; sig_len];
    rng.fill_bytes(&mut signature);
    Signature {
        signature,
        vector_commitment_index: rng.gen::<u64>(),
        proof: gen_single_leaf_proof(rng),
        verifying_key: gen_falcon_verifier(rng),
    }
}

fn gen_signer_context(rng: &mut ChaCha20Rng) -> SignerContext {
    SignerContext {
        first_valid: rng.gen::<u64>(),
        key_lifetime: rng.gen::<u64>(),
        tree: gen_tree(rng),
    }
}

fn gen_secrets(rng: &mut ChaCha20Rng) -> Secrets {
    // `Secrets::to_msgpack`/`from_msgpack` serialize only the embedded
    // `SignerContext` — `ephemeral_keys` is never on the wire (matching
    // go's Secrets/OneTimeSignatureSecrets-style DB-backed key storage) and
    // `from_msgpack` always reconstructs it empty with a zero offset, so
    // the generator must match that shape for the round-trip to be exact.
    Secrets {
        ephemeral_keys: Vec::new(),
        signer_context: gen_signer_context(rng),
        first_key_offset: 0,
    }
}

/// Encode a single `(round, FalconSigner)` pair as the one-element wire
/// array that [`decode_state_proof_keys`] expects — i.e. go's real
/// `merklesignature.KeyRoundPair{Round, Key: *FalconSigner}`
/// (`crypto/merklesignature/merkleSignatureScheme.go:88`), the type behind
/// go's `TestRandomizedEncodingKeyRoundPair`. This is distinct from Rust's
/// `merklesig::KeyRoundPair` (round + `FalconVerifier`), which models the
/// unexported merkle-leaf helper go builds inside
/// `committablePublicKeyArray.Marshal`, not the wire-serialized type.
fn encode_key_round_pair_wire(round: u64, signer: &FalconSigner) -> Vec<u8> {
    let mut buf = Vec::new();
    rmp::encode::write_array_len(&mut buf, 1).unwrap();
    buf.push(0x82); // fixmap, 2 entries: "rnd", "key"
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, round).unwrap();
    rmp::encode::write_str(&mut buf, "key").unwrap();
    buf.extend_from_slice(&signer.to_msgpack());
    buf
}

// ── merklearray ──────────────────────────────────────────────────────────

#[test]
fn hash_factory_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_0001,
        gen_hash_factory,
        HashFactory::encode_msgpack,
        |data| HashFactory::decode_msgpack(data).unwrap().0,
    );
}

#[test]
fn proof_randomized_roundtrip() {
    assert_randomized_roundtrip(0x8261_0002, gen_proof, Proof::encode_msgpack, |data| {
        Proof::decode_msgpack(data).unwrap().0
    });
}

#[test]
fn single_leaf_proof_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_0003,
        gen_single_leaf_proof,
        SingleLeafProof::encode_msgpack,
        |data| SingleLeafProof::decode_msgpack(data).unwrap().0,
    );
}

#[test]
fn tree_randomized_roundtrip() {
    assert_randomized_roundtrip(0x8261_0004, gen_tree, Tree::encode_msgpack, |data| {
        Tree::decode_msgpack(data).unwrap().0
    });
}

// ── merklesig ────────────────────────────────────────────────────────────

#[test]
fn falcon_signer_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_0005,
        gen_falcon_signer,
        FalconSigner::to_msgpack,
        |data| FalconSigner::from_msgpack(data).unwrap().0,
    );
}

#[test]
fn falcon_verifier_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_0006,
        gen_falcon_verifier,
        FalconVerifier::to_msgpack,
        |data| FalconVerifier::from_msgpack(data).unwrap().0,
    );
}

#[test]
fn verifier_randomized_roundtrip() {
    // Also covers go's `TestRandomizedEncodingCommitment`: `commitment` here
    // *is* a `Commitment` ([64]byte) — there is no separate standalone
    // Rust type/codec to exercise beyond this field.
    assert_randomized_roundtrip(0x8261_0007, gen_verifier, Verifier::to_msgpack, |data| {
        Verifier::from_msgpack(data).unwrap().0
    });
}

#[test]
fn signature_randomized_roundtrip() {
    assert_randomized_roundtrip(0x8261_0008, gen_signature, Signature::to_msgpack, |data| {
        Signature::from_msgpack(data).unwrap().0
    });
}

#[test]
fn signer_context_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_0009,
        gen_signer_context,
        SignerContext::to_msgpack,
        |data| SignerContext::from_msgpack(data).unwrap().0,
    );
}

#[test]
fn secrets_randomized_roundtrip() {
    assert_randomized_roundtrip(0x8261_000a, gen_secrets, Secrets::to_msgpack, |data| {
        Secrets::from_msgpack(data).unwrap().0
    });
}

#[test]
fn key_round_pair_randomized_roundtrip() {
    assert_randomized_roundtrip(
        0x8261_000b,
        |rng| (rng.gen::<u64>(), gen_falcon_signer(rng)),
        |(round, signer)| encode_key_round_pair_wire(*round, signer),
        |data| {
            let mut decoded = decode_state_proof_keys(data).unwrap();
            assert_eq!(decoded.len(), 1, "expected exactly one decoded pair");
            decoded.pop().unwrap()
        },
    );
}
