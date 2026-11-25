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

//! `SaltedKeySig` unit tests ported from go-algorand v5.1.1's
//! `data/transactions/sksig_test.go` and `sig_scheme_test.go` (issues #2546,
//! #2547): one fixture per signing scheme (`f1`, `f5`, `ed`), each test run for
//! every scheme, as go's `makeSaltedKeySigTestFixtures` does.
//!
//! Go's `Verify`/`BatchPrep` take the transaction; here the signed message is
//! the same raw `"TX" || canonical(txn)` bytes ([`verify_sksig_bytes`]).

use super::*;
use algo_types::{canonical_address_salt, salted_address, AddressSalt, Transaction, TxnType};
use ed25519_dalek::Signer;
use serde_bytes::ByteBuf;

/// The signing side of a fixture: go's `basics_testing.SigSchemeSigner`.
pub(super) enum TestSigner {
    Falcon1024(Vec<u8>),
    Falcon512(Vec<u8>),
    Ed25519(ed25519_dalek::SigningKey),
}

impl TestSigner {
    pub(super) fn sign_bytes(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            TestSigner::Falcon1024(sk) => algo_falcon::falcon_sign(sk, msg).expect("sign f1"),
            TestSigner::Falcon512(sk) => algo_falcon::falcon512_sign(sk, msg).expect("sign f5"),
            TestSigner::Ed25519(sk) => sk.sign(msg).to_bytes().to_vec(),
        }
    }
}

pub(super) struct Fixture {
    pub(super) name: &'static str,
    pub(super) signer: TestSigner,
    pub(super) proto: ConsensusParams,
    pub(super) txn: Transaction,
    pub(super) authorizer: Address,
    pub(super) sksig: SaltedKeySig,
}

/// go's `config.Consensus[protocol.ConsensusFuture]` for the scheme flags.
pub(super) fn future_proto() -> ConsensusParams {
    ConsensusParams {
        enable_pq_scheme_falcon1024: true,
        enable_sig_scheme_falcon512: true,
        enable_sig_scheme_ed25519: true,
        enable_sig_scheme_logic_sig: true,
        ..Default::default()
    }
}

pub(super) fn tx_message(txn: &Transaction) -> Vec<u8> {
    let mut msg = TX_PREFIX.to_vec();
    msg.extend_from_slice(&canonical_encode_transaction(txn));
    msg
}

pub(super) fn make_fixture(first_seed_byte: u8, scheme: [u8; 2]) -> Fixture {
    let seed = [first_seed_byte; 32];
    let (name, signer, pk) = match &scheme {
        b"f1" => {
            let (pk, sk) = algo_falcon::falcon_keygen(&seed).expect("keygen f1");
            ("Falcon1024", TestSigner::Falcon1024(sk), pk)
        }
        b"f5" => {
            let (pk, sk) = algo_falcon::falcon512_keygen(&seed).expect("keygen f5");
            ("Falcon512", TestSigner::Falcon512(sk), pk)
        }
        b"ed" => {
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key().to_bytes().to_vec();
            ("Ed25519", TestSigner::Ed25519(sk), pk)
        }
        other => panic!("no signing fixture for {other:?}"),
    };
    let (salt, authorizer) = canonical_address_salt(scheme, &pk).expect("canonical salt");
    let txn = Transaction {
        txn_type: TxnType::from("pay"),
        sender: authorizer,
        receiver: authorizer,
        ..Default::default()
    };
    let signature = signer.sign_bytes(&tx_message(&txn));
    let proto = future_proto();
    assert!(proto.sig_scheme_enabled(scheme));
    Fixture {
        name,
        signer,
        proto,
        txn,
        authorizer,
        sksig: SaltedKeySig {
            scheme,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(signature),
        },
    }
}

fn fixtures(first_seed_byte: u8) -> Vec<Fixture> {
    [*b"f1", *b"f5", *b"ed"]
        .into_iter()
        .map(|s| make_fixture(first_seed_byte, s))
        .collect()
}

pub(super) fn disable(proto: &ConsensusParams, scheme: [u8; 2]) -> ConsensusParams {
    let mut p = proto.clone();
    match &scheme {
        b"f1" => p.enable_pq_scheme_falcon1024 = false,
        b"f5" => p.enable_sig_scheme_falcon512 = false,
        b"ed" => p.enable_sig_scheme_ed25519 = false,
        b"ls" => p.enable_sig_scheme_logic_sig = false,
        _ => unreachable!(),
    }
    p
}

/// The verdict text of [`verify_sksig_bytes`]: go's error string, with a failed
/// ed25519 signature reading as the bare batch text (`Batch`).
fn verify_text(
    f: &Fixture,
    sksig: &SaltedKeySig,
    txn: &Transaction,
    authorizer: &Address,
) -> Result<(), String> {
    verify_sksig_bytes(sksig, &tx_message(txn), authorizer, &f.proto).map_err(|e| match e {
        SksigFailure::Prep(e) => validation_text(e),
        SksigFailure::Batch => algo_error::BATCH_HAS_FAILED_SIGS.to_string(),
    })
}

pub(super) fn flip_first(b: &ByteBuf) -> ByteBuf {
    let mut v = b.to_vec();
    v[0] ^= 1;
    ByteBuf::from(v)
}

const UNKNOWN: [u8; 2] = *b"x1";

// ---- sig_scheme_test.go --------------------------------------------------

// go's `TestSigSchemesMatchTestSchemes`: the scheme table and the schemes the
// tests exercise are in step, every scheme is supported with bounds, and an
// unknown tag is not.
#[test]
fn sig_schemes_match_test_schemes() {
    let signing = [*b"f1", *b"f5", *b"ed"];
    for tag in signing.into_iter().chain([*b"ls"]) {
        assert!(SigScheme::lookup(tag).is_some(), "{tag:?}");
    }
    assert_eq!(
        fixtures(1).len(),
        3,
        "go's SigSchemeTests holds the signing schemes: all but ls"
    );
    assert!(SigScheme::lookup(UNKNOWN).is_none());
    assert!(!future_proto().sig_scheme_enabled(UNKNOWN));
}

// go's `TestSigSchemeBoundsCoverSchemes`: a real key and signature fit their scheme's bounds.
#[test]
fn sig_scheme_bounds_cover_schemes() {
    for f in fixtures(1) {
        let scheme = SigScheme::lookup(f.sksig.scheme).unwrap();
        assert!(
            f.sksig.public_key.len() <= scheme.max_public_key_size(),
            "{}",
            f.name
        );
        assert!(
            f.sksig.signature.len() <= scheme.max_signature_size(),
            "{}",
            f.name
        );
    }
}

// go's `TestSigSchemeLogicSigFee`: the ls scheme never carries a surcharge.
#[test]
fn sig_scheme_logic_sig_fee_is_zero_everywhere() {
    for name in [
        algo_types::consensus::CONSENSUS_V7,
        algo_types::consensus::CONSENSUS_V12,
        algo_types::consensus::CONSENSUS_V40,
        algo_types::consensus::CONSENSUS_FUTURE,
    ] {
        let p = algo_types::consensus::consensus_params_for_version(name).expect("known protocol");
        assert_eq!(p.sig_scheme_fee_contribution(*b"ls"), 0, "{name}");
    }
    assert_eq!(future_proto().sig_scheme_fee_contribution(*b"ls"), 0);
}

// ---- sksig_test.go: the envelope -----------------------------------------

#[test]
fn salted_key_sig_blank() {
    assert!(SaltedKeySig::default().blank());
    assert!(SaltedKeySig {
        salt: AddressSalt(0),
        ..Default::default()
    }
    .blank());
    assert!(!SaltedKeySig {
        salt: AddressSalt(1),
        ..Default::default()
    }
    .blank());
    for scheme in [*b"f1", *b"f5", *b"ed"] {
        assert!(!SaltedKeySig {
            scheme,
            ..Default::default()
        }
        .blank());
    }
    assert!(!SaltedKeySig {
        public_key: ByteBuf::from(vec![1]),
        ..Default::default()
    }
    .blank());
    assert!(!SaltedKeySig {
        signature: ByteBuf::from(vec![1]),
        ..Default::default()
    }
    .blank());
}

#[test]
fn salted_key_sig_equal() {
    for f in fixtures(0) {
        let same = f.sksig.clone();
        assert_eq!(f.sksig, same, "{}", f.name);
        let mut c = f.sksig.clone();
        c.scheme = UNKNOWN;
        assert_ne!(f.sksig, c, "{}: scheme", f.name);
        let mut c = f.sksig.clone();
        c.salt = AddressSalt(c.salt.0.wrapping_add(1));
        assert_ne!(f.sksig, c, "{}: salt", f.name);
        let mut c = f.sksig.clone();
        c.public_key = flip_first(&c.public_key);
        assert_ne!(f.sksig, c, "{}: public key", f.name);
        let mut c = f.sksig.clone();
        c.signature = flip_first(&c.signature);
        assert_ne!(f.sksig, c, "{}: signature", f.name);
        assert_eq!(SaltedKeySig::default(), SaltedKeySig::default());
        assert_ne!(SaltedKeySig::default(), f.sksig);
    }
}

#[test]
fn salted_key_sig_authorizer_address() {
    for f in fixtures(0) {
        assert_eq!(f.authorizer, f.sksig.address(), "{}", f.name);
        assert_eq!(
            salted_address(f.sksig.scheme, f.sksig.salt, &f.sksig.public_key),
            f.sksig.address(),
            "{}",
            f.name
        );
    }
}

#[test]
fn salted_key_sig_validate_envelope() {
    for f in fixtures(0) {
        let n = f.name;
        validate_sksig_scheme(&f.sksig, &f.proto).unwrap_or_else(|e| panic!("{n}: {e}"));
        let scheme_only = SaltedKeySig {
            scheme: f.sksig.scheme,
            ..Default::default()
        };
        validate_sksig_scheme(&scheme_only, &f.proto).unwrap();
        validate_sksig_envelope(&f.sksig, &f.authorizer, &f.proto).unwrap();
        // the envelope checks no signature bytes
        let mut no_sig = f.sksig.clone();
        no_sig.signature = ByteBuf::new();
        validate_sksig_envelope(&no_sig, &f.authorizer, &f.proto).unwrap();

        let disabled = disable(&f.proto, f.sksig.scheme);
        let e = validate_sksig_scheme(&f.sksig, &disabled)
            .unwrap_err()
            .to_string();
        assert!(e.contains("signature scheme not enabled"), "{n}: {e}");
        let e = validate_sksig_envelope(&f.sksig, &f.authorizer, &disabled)
            .unwrap_err()
            .to_string();
        assert!(e.contains("signature scheme not enabled"), "{n}: {e}");

        let mut unknown = f.sksig.clone();
        unknown.scheme = UNKNOWN;
        let e = validate_sksig_scheme(&unknown, &f.proto)
            .unwrap_err()
            .to_string();
        assert!(e.contains("signature scheme not supported"), "{n}: {e}");
        let e = validate_sksig_envelope(&unknown, &unknown.address(), &f.proto)
            .unwrap_err()
            .to_string();
        assert!(e.contains("signature scheme not supported"), "{n}: {e}");

        // a malformed key still has a valid envelope for its own address; it
        // fails when the signature is checked, and not as an address mismatch
        let mut malformed = f.sksig.clone();
        let pk_len = malformed.public_key.len();
        malformed.public_key = ByteBuf::from(malformed.public_key[..pk_len - 1].to_vec());
        validate_sksig_envelope(&malformed, &malformed.address(), &f.proto).unwrap();
        assert!(
            verify_text(&f, &malformed, &f.txn, &malformed.address()).is_err(),
            "{n}"
        );

        let wrong = Address([1u8; 32]);
        let e = validate_sksig_envelope(&f.sksig, &wrong, &f.proto)
            .unwrap_err()
            .to_string();
        assert!(e.contains("authorizer mismatch"), "{n}: {e}");

        // a corrupt signature passes the envelope but not verification
        let mut corrupt = f.sksig.clone();
        corrupt.signature = flip_first(&corrupt.signature);
        validate_sksig_envelope(&corrupt, &f.authorizer, &f.proto).unwrap();
        assert!(
            verify_text(&f, &corrupt, &f.txn, &f.authorizer).is_err(),
            "{n}"
        );

        let e = validate_sksig_envelope(&SaltedKeySig::default(), &f.authorizer, &f.proto)
            .unwrap_err()
            .to_string();
        assert!(e.contains("salted-key signature is blank"), "{n}: {e}");
        let e = validate_sksig_scheme(&SaltedKeySig::default(), &f.proto)
            .unwrap_err()
            .to_string();
        assert!(e.contains("salted-key signature is blank"), "{n}: {e}");
    }
}

// go's `TestSaltedKeySigLogicSigScheme`: the ls envelope validates like any
// scheme, but signature-byte verification refuses it.
#[test]
fn salted_key_sig_logic_sig_scheme() {
    let proto = future_proto();
    let program = vec![0x0e, 0x81, 0x01]; // #pragma version 14; pushint 1
    let (salt, authorizer) = canonical_address_salt(*b"ls", &program).expect("canonical salt");
    assert!(authorizer.is_off_ed25519_curve());
    let sksig = SaltedKeySig {
        scheme: *b"ls",
        salt,
        public_key: ByteBuf::from(program),
        signature: ByteBuf::new(),
    };
    assert_eq!(authorizer, sksig.address());
    validate_sksig_envelope(&sksig, &authorizer, &proto).unwrap();
    let e = validate_sksig_envelope(&sksig, &Address([1u8; 32]), &proto)
        .unwrap_err()
        .to_string();
    assert!(e.contains("authorizer mismatch"), "{e}");
    let e = validate_sksig_envelope(&sksig, &authorizer, &disable(&proto, *b"ls"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("signature scheme not enabled"), "{e}");

    // args are not signature bytes: no caller may authorize ls by verifying them
    let mut with_args = sksig.clone();
    with_args.signature = ByteBuf::from(b"args".to_vec());
    let txn = Transaction {
        txn_type: TxnType::from("pay"),
        sender: authorizer,
        receiver: authorizer,
        ..Default::default()
    };
    let f = make_fixture(0, *b"ed");
    let e = verify_text(&f, &with_args, &txn, &authorizer).unwrap_err();
    assert!(
        e.contains("logic signature must be verified by evaluating its program"),
        "{e}"
    );
}

// ---- sksig_test.go: Verify / BatchPrep -----------------------------------

#[test]
fn salted_key_sig_verify() {
    for f in fixtures(0) {
        verify_text(&f, &f.sksig, &f.txn, &f.authorizer)
            .unwrap_or_else(|e| panic!("{}: {e}", f.name));
    }
}

// go's `TestSaltedKeySigBatchPrep`: ed25519 is the batched scheme, Falcon is
// verified on its own. Here the difference shows in the failure: a failed
// ed25519 signature is the bare batch text, a failed Falcon one its own.
#[test]
fn salted_key_sig_batch_prep_batches_only_ed25519() {
    let ed = make_fixture(1, *b"ed");
    let mut bad = ed.sksig.clone();
    bad.signature = flip_first(&bad.signature);
    let e = verify_text(&ed, &bad, &ed.txn, &ed.authorizer).unwrap_err();
    assert_eq!(e, algo_error::BATCH_HAS_FAILED_SIGS);
    verify_text(&ed, &ed.sksig, &ed.txn, &ed.authorizer).unwrap();

    let falcon = make_fixture(1, *b"f1");
    let mut bad = falcon.sksig.clone();
    bad.signature = flip_first(&bad.signature);
    let e = verify_text(&falcon, &bad, &falcon.txn, &falcon.authorizer).unwrap_err();
    assert_ne!(e, algo_error::BATCH_HAS_FAILED_SIGS);
    assert!(e.contains("falcon-1024 invalid signature"), "{e}");
}

// go's `TestSaltedKeySigBatchPrepMatchesVerifyEnvelopeErrors`: batching and
// single verification fail an envelope problem with the same error; algod-rust
// has the one path, so the texts are the envelope's own.
#[test]
fn salted_key_sig_envelope_errors_are_the_same_on_every_path() {
    let f = make_fixture(2, *b"ed");
    let mut unsupported = f.sksig.clone();
    unsupported.scheme = UNKNOWN;
    let mut empty = f.sksig.clone();
    empty.signature = ByteBuf::new();
    let mut wrong = f.authorizer;
    wrong.0[0] ^= 1;
    let disabled = disable(&f.proto, *b"ed");
    let cases: [(&str, SaltedKeySig, &ConsensusParams, Address, &str); 5] = [
        (
            "blank",
            SaltedKeySig::default(),
            &f.proto,
            f.authorizer,
            "salted-key signature is blank",
        ),
        (
            "unsupported",
            unsupported,
            &f.proto,
            f.authorizer,
            "signature scheme not supported",
        ),
        (
            "disabled",
            f.sksig.clone(),
            &disabled,
            f.authorizer,
            "signature scheme not enabled",
        ),
        (
            "authorizer-mismatch",
            f.sksig.clone(),
            &f.proto,
            wrong,
            "authorizer mismatch",
        ),
        (
            "empty-signature",
            empty,
            &f.proto,
            f.authorizer,
            "salted-key signature is empty",
        ),
    ];
    for (name, sksig, proto, authorizer, want) in cases {
        let e = match verify_sksig_bytes(&sksig, &tx_message(&f.txn), &authorizer, proto) {
            Err(SksigFailure::Prep(e)) => validation_text(e),
            Ok(()) => panic!("{name}: verified"),
            Err(SksigFailure::Batch) => panic!("{name}: batch failure"),
        };
        assert!(e.contains(want), "{name}: {e}");
    }
}

// go's `TestSaltedKeySigVerifyAcceptsSignatureOverRawTxn`: the signature is over
// the raw `"TX" || canonical(txn)`, never over the txid.
#[test]
fn salted_key_sig_verify_accepts_signature_over_raw_txn() {
    for f in fixtures(0) {
        let raw = f.signer.sign_bytes(&tx_message(&f.txn));
        assert_eq!(
            raw.as_slice(),
            f.sksig.signature.as_slice(),
            "{}: deterministic over the raw txn",
            f.name
        );
        let mut s = f.sksig.clone();
        s.signature = ByteBuf::from(raw.clone());
        verify_text(&f, &s, &f.txn, &f.authorizer).unwrap();

        // a signature over the txid digest must not verify
        let txid = algo_codec::compute_txn_id(&f.txn);
        let over_txid = f.signer.sign_bytes(&txid.0);
        assert_ne!(over_txid, raw, "{}", f.name);
        s.signature = ByteBuf::from(over_txid);
        assert!(
            verify_text(&f, &s, &f.txn, &f.authorizer).is_err(),
            "{}",
            f.name
        );
    }
}

#[test]
fn salted_key_sig_verify_checks_consensus_params() {
    for f in fixtures(0) {
        verify_text(&f, &f.sksig, &f.txn, &f.authorizer).unwrap();
        let disabled = ConsensusParams {
            ..disable(&f.proto, f.sksig.scheme)
        };
        let e = verify_sksig_bytes(&f.sksig, &tx_message(&f.txn), &f.authorizer, &disabled);
        match e {
            Err(SksigFailure::Prep(e)) => assert!(
                validation_text(e).contains("signature scheme not enabled"),
                "{}",
                f.name
            ),
            _ => panic!("{}: expected a prep failure", f.name),
        }
    }
}

#[test]
fn salted_key_sig_verify_rejects_blank_empty_unsupported_and_mismatch() {
    for f in fixtures(0) {
        let n = f.name;
        let e = verify_text(&f, &SaltedKeySig::default(), &f.txn, &f.authorizer).unwrap_err();
        assert!(e.contains("salted-key signature is blank"), "{n}: {e}");

        let mut empty = f.sksig.clone();
        empty.signature = ByteBuf::new();
        let e = verify_text(&f, &empty, &f.txn, &f.authorizer).unwrap_err();
        assert!(e.contains("salted-key signature is empty"), "{n}: {e}");

        let mut unsupported = f.sksig.clone();
        unsupported.scheme = UNKNOWN;
        unsupported.signature = ByteBuf::from(vec![1]);
        let e = verify_text(&f, &unsupported, &f.txn, &unsupported.address()).unwrap_err();
        assert!(e.contains("signature scheme not supported"), "{n}: {e}");

        let wrong = Address([1u8; 32]);
        assert_ne!(f.authorizer, wrong);
        let e = verify_text(&f, &f.sksig, &f.txn, &wrong).unwrap_err();
        assert!(e.contains("authorizer mismatch"), "{n}: {e}");
    }
}

#[test]
fn salted_key_sig_verify_rejects_malformed_public_key_and_signature() {
    for f in fixtures(0) {
        let n = f.name;
        // one byte short key (its own address), not an address mismatch
        let mut short_pk = f.sksig.clone();
        let l = short_pk.public_key.len();
        short_pk.public_key = ByteBuf::from(short_pk.public_key[..l - 1].to_vec());
        let e = verify_text(&f, &short_pk, &f.txn, &short_pk.address()).unwrap_err();
        assert!(!e.contains("authorizer mismatch"), "{n}: {e}");

        // a signature too long for the scheme never reaches its verifier
        let scheme = SigScheme::lookup(f.sksig.scheme).unwrap();
        let mut sig = f.sksig.clone();
        sig.signature = ByteBuf::from(vec![0u8; scheme.max_signature_size() + 1]);
        let e = verify_text(&f, &sig, &f.txn, &f.authorizer).unwrap_err();
        assert!(
            e.contains("field too large for scheme: signature size"),
            "{n}: {e}"
        );

        // one that fits, but is garbage, is rejected by the verifier
        sig.signature = ByteBuf::from(vec![0u8; scheme.max_signature_size()]);
        assert!(verify_text(&f, &sig, &f.txn, &f.authorizer).is_err(), "{n}");
    }
}

#[test]
fn salted_key_sig_verify_rejects_changed_transaction_and_signature() {
    for f in fixtures(0) {
        let mut txn = f.txn.clone();
        txn.note = ByteBuf::from(b"changed".to_vec());
        assert!(
            verify_text(&f, &f.sksig, &txn, &f.authorizer).is_err(),
            "{}: txn",
            f.name
        );

        let mut s = f.sksig.clone();
        let mut sig = s.signature.to_vec();
        *sig.last_mut().unwrap() ^= 1;
        s.signature = ByteBuf::from(sig);
        assert!(
            verify_text(&f, &s, &f.txn, &f.authorizer).is_err(),
            "{}: signature",
            f.name
        );
    }
}

// go's `TestSaltedKeySigSchemeSizeLimits`: the envelope holds each scheme to its
// own size limits (tighter than the wire bound for all but the largest scheme);
// for ls, the largest program and the largest set of arguments LogicSig allows
// still fit.
#[test]
fn salted_key_sig_scheme_size_limits() {
    use algo_types::go_msgp as g;
    let proto = future_proto();
    let ed = make_fixture(1, *b"ed");
    let mut ed_sig = ed.sksig.clone();
    ed_sig.signature = ByteBuf::from(vec![0u8; g::ED25519_SIGNATURE_SIZE]);
    validate_sksig_envelope(&ed_sig, &ed.authorizer, &proto).unwrap();
    let mut long = ed_sig.clone();
    long.signature = ByteBuf::from(vec![0u8; g::ED25519_SIGNATURE_SIZE + 1]);
    let e = validate_sksig_envelope(&long, &ed.authorizer, &proto)
        .unwrap_err()
        .to_string();
    assert!(e.contains("too large for scheme"), "{e}");

    let max_program = g::bounds::MAX_LOGIC_SIG_MAX_SIZE.get();
    let mut program = vec![0u8; max_program];
    program[0] = 0x0e; // #pragma version 14
    let (salt, authorizer) = algo_types::canonical_address_salt(*b"ls", &program).unwrap();
    // 255 arguments sharing the whole LogicSig size budget
    let mut args: Vec<Option<Vec<u8>>> = Vec::new();
    let mut remaining = max_program;
    for i in 0..g::EVAL_MAX_ARGS {
        let n = remaining / (g::EVAL_MAX_ARGS - i);
        args.push(Some(vec![0u8; n]));
        remaining -= n;
    }
    let ls = SaltedKeySig {
        scheme: *b"ls",
        salt,
        public_key: ByteBuf::from(program.clone()),
        signature: ByteBuf::from(algo_codec::encode_logic_sig_args(&args)),
    };
    validate_sksig_envelope(&ls, &authorizer, &proto).unwrap();

    let mut over = ls.clone();
    program.push(1);
    let (salt, authorizer) = algo_types::canonical_address_salt(*b"ls", &program).unwrap();
    over.public_key = ByteBuf::from(program);
    over.salt = salt;
    let e = validate_sksig_envelope(&over, &authorizer, &proto)
        .unwrap_err()
        .to_string();
    assert!(e.contains("too large for scheme"), "{e}");
}
