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

//! Transaction-level `SaltedKeySig` tests ported from go-algorand v5.1.1's
//! `data/transactions/verify/txn_test.go` (`TestTxnValidation*SaltedKeySig*`,
//! `TestTxnGroupSaltedKeySigMixedSignatures`; issues #2546, #2547): a transaction
//! authorized by a top-level SaltedKeySig or one delegated through a LogicSig,
//! verified through [`verify_transaction_signature`], for every signing scheme.

use super::sksig_tests::{disable, flip_first, future_proto, make_fixture, tx_message};
use super::*;
use algo_types::{AddressSalt, Transaction, TxnType};
use serde_bytes::ByteBuf;

fn pay(sender: Address, receiver: Address) -> Transaction {
    Transaction {
        txn_type: TxnType::from("pay"),
        sender,
        receiver,
        fee: 1000,
        first_valid: algo_types::Round(40),
        last_valid: algo_types::Round(60),
        ..Default::default()
    }
}

/// go's `makeSKsigSignedTxnForScheme`.
fn sksig_txn(first_seed_byte: u8, scheme: [u8; 2]) -> SignedTransaction {
    let f = make_fixture(first_seed_byte, scheme);
    let txn = pay(f.authorizer, Address([1u8; 32]));
    let mut sksig = f.sksig.clone();
    sksig.signature = ByteBuf::from(f.signer.sign_bytes(&tx_message(&txn)));
    SignedTransaction {
        txn,
        pqsig: Some(sksig),
        ..Default::default()
    }
}

/// go's `makeSaltedKeySigDelegatedLogicSigTxnForScheme`: `int 1` (v1) delegated
/// by the salted-key account.
fn delegated_txn(first_seed_byte: u8, scheme: [u8; 2]) -> SignedTransaction {
    let f = make_fixture(first_seed_byte, scheme);
    let program = algo_avm::assemble_string("#pragma version 1\nint 1")
        .expect("assembles")
        .program;
    let delegation = SKsigDelegatedProgram {
        addr: f.authorizer,
        program: program.clone(),
    };
    let mut sksig = f.sksig.clone();
    sksig.signature = ByteBuf::from(f.signer.sign_bytes(&delegation.to_be_signed()));
    SignedTransaction {
        txn: pay(f.authorizer, Address([1u8; 32])),
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program),
            pqsig: Some(sksig),
            ..LogicSig::default()
        }),
        ..Default::default()
    }
}

fn verify(stx: &SignedTransaction, consensus: &ConsensusParams) -> Result<(), String> {
    let group = [stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);
    verify_transaction_signature(stx, &group, 0, &mut budget, consensus).map_err(validation_text)
}

const SCHEMES: [[u8; 2]; 3] = [*b"f1", *b"f5", *b"ed"];

fn batched(scheme: [u8; 2]) -> bool {
    &scheme == b"ed"
}

/// go's `invalidSaltedKeySigErrText`.
fn invalid_text(scheme: [u8; 2]) -> &'static str {
    if batched(scheme) {
        algo_error::BATCH_HAS_FAILED_SIGS
    } else {
        "invalid signature"
    }
}

#[test]
fn txn_validation_salted_key_sig_and_scheme_enablement() {
    for scheme in SCHEMES {
        let stx = sksig_txn(0, scheme);
        verify(&stx, &future_proto()).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));
        let e = verify(&stx, &disable(&future_proto(), scheme)).unwrap_err();
        assert!(
            e.contains("salted-key signature validation failed"),
            "{scheme:?}: {e}"
        );
        assert!(
            e.contains("signature scheme not enabled"),
            "{scheme:?}: {e}"
        );
    }
}

#[test]
fn txn_validation_ed25519_salted_key_sig_and_its_delegated_logic_sig() {
    let mut stx = sksig_txn(0, *b"ed");
    verify(&stx, &future_proto()).unwrap();
    let sk = stx.pqsig.as_mut().unwrap();
    sk.signature = flip_first(&sk.signature);
    assert_eq!(
        verify(&stx, &future_proto()).unwrap_err(),
        algo_error::BATCH_HAS_FAILED_SIGS
    );

    let mut stx = delegated_txn(1, *b"ed");
    verify(&stx, &future_proto()).unwrap();
    let sk = stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap();
    sk.signature = flip_first(&sk.signature);
    assert_eq!(
        verify(&stx, &future_proto()).unwrap_err(),
        algo_error::BATCH_HAS_FAILED_SIGS
    );
}

// go's `TestTxnValidationMixedEd25519Batch`: a group of a plain ed25519
// signature, an ed salted-key one and a Falcon one; spoiling the salted ed25519
// signature is what the batch reports.
#[test]
fn txn_validation_mixed_ed25519_batch() {
    use ed25519_dalek::Signer as _;
    let regular = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let regular_addr = Address(regular.verifying_key().to_bytes());
    let mut txns = vec![
        pay(regular_addr, Address([1u8; 32])),
        pay(make_fixture(2, *b"ed").authorizer, Address([2u8; 32])),
        pay(make_fixture(3, *b"f1").authorizer, Address([3u8; 32])),
    ];
    let hashes: Vec<algo_types::Digest> = txns.iter().map(algo_codec::compute_txn_id).collect();
    let group_id = algo_codec::compute_group_id_from_hashes(&hashes);
    for t in &mut txns {
        t.group = group_id.0;
    }
    let plain_sig = regular.sign(&tx_message(&txns[0])).to_bytes();
    let signed = |seed: u8, scheme: [u8; 2], txn: &Transaction| {
        let f = make_fixture(seed, scheme);
        let mut sk = f.sksig.clone();
        sk.signature = ByteBuf::from(f.signer.sign_bytes(&tx_message(txn)));
        SignedTransaction {
            txn: txn.clone(),
            pqsig: Some(sk),
            ..Default::default()
        }
    };
    let mut group = vec![
        SignedTransaction {
            txn: txns[0].clone(),
            sig: plain_sig,
            ..Default::default()
        },
        signed(2, *b"ed", &txns[1]),
        signed(3, *b"f1", &txns[2]),
    ];
    let proto = future_proto();
    for i in 0..group.len() {
        let mut budget = GroupBudget::for_logicsig(3);
        verify_transaction_signature(&group[i], &group, i, &mut budget, &proto)
            .unwrap_or_else(|e| panic!("member {i}: {e}"));
    }
    let sk = group[1].pqsig.as_mut().unwrap();
    sk.signature = flip_first(&sk.signature);
    let mut budget = GroupBudget::for_logicsig(3);
    let e = verify_transaction_signature(&group[1], &group, 1, &mut budget, &proto).unwrap_err();
    assert_eq!(validation_text(e), algo_error::BATCH_HAS_FAILED_SIGS);
}

#[test]
fn txn_validation_ed25519_rejects_wrong_lengths() {
    // public key one byte short (sender follows the new address)
    let mut stx = sksig_txn(4, *b"ed");
    let sk = stx.pqsig.as_mut().unwrap();
    let l = sk.public_key.len();
    sk.public_key = ByteBuf::from(sk.public_key[..l - 1].to_vec());
    stx.txn.sender = sk.address();
    let e = verify(&stx, &future_proto()).unwrap_err();
    assert!(e.contains("salted-key signature validation failed"), "{e}");
    assert!(e.contains("ed25519 invalid signature"), "{e}");
    // signature one byte short
    let mut stx = sksig_txn(4, *b"ed");
    let sk = stx.pqsig.as_mut().unwrap();
    let l = sk.signature.len();
    sk.signature = ByteBuf::from(sk.signature[..l - 1].to_vec());
    let e = verify(&stx, &future_proto()).unwrap_err();
    assert!(e.contains("salted-key signature validation failed"), "{e}");
    assert!(e.contains("ed25519 invalid signature"), "{e}");
}

// go's `TestTxnValidationSaltedKeySigSchemeBoundary`: at the released v42 only
// falcon-1024 is enabled.
#[test]
fn txn_validation_salted_key_sig_scheme_boundary_at_v42() {
    let v42 =
        algo_types::consensus::consensus_params_for_version(algo_types::consensus::CONSENSUS_V42)
            .expect("v42");
    assert!(v42.sig_scheme_enabled(*b"f1"));
    assert!(!v42.sig_scheme_enabled(*b"f5"));
    assert!(!v42.sig_scheme_enabled(*b"ed"));

    verify(&sksig_txn(0, *b"f1"), &v42).expect("falcon-1024 txn");
    verify(&delegated_txn(1, *b"f1"), &v42).expect("falcon-1024 lsig");
    for (i, scheme) in [*b"f5", *b"ed"].into_iter().enumerate() {
        let e = verify(&sksig_txn(i as u8 + 2, scheme), &v42).unwrap_err();
        assert!(
            e.contains("salted-key signature validation failed"),
            "{scheme:?}: {e}"
        );
        assert!(
            e.contains("signature scheme not enabled"),
            "{scheme:?}: {e}"
        );
        let e = verify(&delegated_txn(i as u8 + 4, scheme), &v42).unwrap_err();
        assert!(
            e.contains("salted-key signature delegation validation failed"),
            "{scheme:?}: {e}"
        );
        assert!(
            e.contains("signature scheme not enabled"),
            "{scheme:?}: {e}"
        );
    }
}

#[test]
fn txn_validation_salted_key_sig_with_auth_addr() {
    // a rekeyed ordinary account authorized by a salted-key signature
    let mut txn = pay(Address([5u8; 32]), Address([6u8; 32]));
    let f = make_fixture(8, *b"f1");
    let mut sk = f.sksig.clone();
    sk.signature = ByteBuf::from(f.signer.sign_bytes(&tx_message(&txn)));
    let mut stx = SignedTransaction {
        txn: txn.clone(),
        auth_addr: Some(f.authorizer),
        pqsig: Some(sk),
        ..Default::default()
    };
    verify(&stx, &future_proto()).unwrap();
    stx.auth_addr = None;
    let e = verify(&stx, &future_proto()).unwrap_err();
    assert!(
        e.contains("salted-key signature authorizer mismatch"),
        "{e}"
    );

    // an ed25519 signature rekeyed by AuthAddr from a salted sender
    use ed25519_dalek::Signer as _;
    let secret = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let key_addr = Address(secret.verifying_key().to_bytes());
    let salted_sender = make_fixture(9, *b"f1").authorizer;
    txn = pay(salted_sender, Address([7u8; 32]));
    let mut stx = SignedTransaction {
        sig: secret.sign(&tx_message(&txn)).to_bytes(),
        txn,
        auth_addr: Some(key_addr),
        ..Default::default()
    };
    verify(&stx, &future_proto()).unwrap();
    stx.auth_addr = None;
    assert!(verify(&stx, &future_proto()).is_err());
}

// go's `TestTxnValidationSaltedKeySigEncodeDecode`.
#[test]
fn txn_validation_salted_key_sig_survives_encode_decode() {
    for scheme in SCHEMES {
        let stx = sksig_txn(1, scheme);
        let encoded = algo_codec::canonical_encode_signed_transaction(&stx);
        let decoded = algo_codec::decode_signed_txn_stream(&encoded)
            .expect("decodes")
            .remove(0);
        assert_eq!(decoded.txn, stx.txn);
        assert_eq!(decoded.pqsig, stx.pqsig);
        verify(&decoded, &future_proto()).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));
    }
}

#[test]
fn txn_validation_salted_key_sig_rejects_a_malformed_proof() {
    for scheme in SCHEMES {
        let mut stx = sksig_txn(2, scheme);
        let sk = stx.pqsig.as_mut().unwrap();
        let l = sk.public_key.len();
        sk.public_key = ByteBuf::from(sk.public_key[..l - 1].to_vec());
        stx.txn.sender = sk.address();
        let e = verify(&stx, &future_proto()).unwrap_err();
        assert!(
            e.contains("salted-key signature validation failed"),
            "{scheme:?}: {e}"
        );

        let mut stx = sksig_txn(3, scheme);
        stx.pqsig.as_mut().unwrap().signature = ByteBuf::from(vec![0u8; 100_000]);
        let e = verify(&stx, &future_proto()).unwrap_err();
        assert!(
            e.contains("salted-key signature validation failed"),
            "{scheme:?}: {e}"
        );
    }
}

#[test]
fn txn_validation_salted_key_sig_delegated_logic_sig() {
    for scheme in SCHEMES {
        let stx = delegated_txn(10, scheme);
        verify(&stx, &future_proto()).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));
        // an ordinary sender authorized by the delegation through AuthAddr
        let mut stx = delegated_txn(11, scheme);
        stx.txn.sender = Address([4u8; 32]);
        stx.auth_addr = Some(stx.lsig.as_ref().unwrap().pqsig.as_ref().unwrap().address());
        verify(&stx, &future_proto()).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));
    }
}

// go's `TestTxnValidationSaltedKeySigDelegatedLogicSigRejectsInvalidProof`.
#[test]
fn txn_validation_delegated_logic_sig_rejects_invalid_proofs() {
    for scheme in SCHEMES {
        let want = |e: &str, contains: &str| {
            // a batched failure is the bare batch text; the rest carry the frame
            if e != algo_error::BATCH_HAS_FAILED_SIGS {
                assert!(
                    e.contains("salted-key signature delegation validation failed"),
                    "{scheme:?}: {e}"
                );
            }
            assert!(e.contains(contains), "{scheme:?}: {e} (want {contains})");
        };
        let proto = future_proto();

        let mut stx = delegated_txn(12, scheme);
        stx.txn.sender = Address([2u8; 32]);
        want(
            &verify(&stx, &proto).unwrap_err(),
            "salted-key signature authorizer mismatch",
        );

        let mut stx = delegated_txn(13, scheme);
        stx.lsig.as_mut().unwrap().logic = ByteBuf::from(
            algo_avm::assemble_string("#pragma version 1\nint 2")
                .unwrap()
                .program,
        );
        want(&verify(&stx, &proto).unwrap_err(), invalid_text(scheme));

        let mut stx = delegated_txn(14, scheme);
        let sk = stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap();
        sk.signature = flip_first(&sk.signature);
        want(&verify(&stx, &proto).unwrap_err(), invalid_text(scheme));

        let mut stx = delegated_txn(15, scheme);
        let sk = stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap();
        let l = sk.public_key.len();
        sk.public_key = ByteBuf::from(sk.public_key[..l - 1].to_vec());
        want(
            &verify(&stx, &proto).unwrap_err(),
            "salted-key signature authorizer mismatch",
        );

        let mut stx = delegated_txn(16, scheme);
        stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap().signature = ByteBuf::new();
        want(
            &verify(&stx, &proto).unwrap_err(),
            "salted-key signature is empty",
        );

        let mut stx = delegated_txn(17, scheme);
        stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap().signature =
            ByteBuf::from(vec![0u8; 100_000]);
        want(&verify(&stx, &proto).unwrap_err(), "too large for scheme");

        let stx = delegated_txn(18, scheme);
        want(
            &verify(&stx, &disable(&proto, scheme)).unwrap_err(),
            "signature scheme not enabled",
        );

        // replaying the signature under another salt
        let mut stx = delegated_txn(19, scheme);
        let sk = stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap();
        let original = sk.address();
        sk.salt = AddressSalt(sk.salt.0.wrapping_add(1));
        stx.txn.sender = sk.address();
        assert_ne!(original, stx.txn.sender);
        want(&verify(&stx, &proto).unwrap_err(), invalid_text(scheme));
    }
}

// go's `TestTxnValidationSaltedKeySigDelegatedLogicSigSignsRawProgram`: the
// delegation signs `"PQProgram" || authorizer || program` itself, not its digest.
#[test]
fn txn_validation_delegated_logic_sig_signs_the_raw_program() {
    for scheme in SCHEMES {
        let f = make_fixture(20, scheme);
        let program = algo_avm::assemble_string("#pragma version 1\nint 1")
            .unwrap()
            .program;
        let delegation = SKsigDelegatedProgram {
            addr: f.authorizer,
            program: program.clone(),
        };
        let raw = f.signer.sign_bytes(&delegation.to_be_signed());
        let mut sk = f.sksig.clone();
        sk.signature = ByteBuf::from(raw.clone());
        let mut stx = SignedTransaction {
            txn: pay(f.authorizer, Address([1u8; 32])),
            lsig: Some(LogicSig {
                logic: ByteBuf::from(program),
                pqsig: Some(sk),
                ..LogicSig::default()
            }),
            ..Default::default()
        };
        verify(&stx, &future_proto()).unwrap_or_else(|e| panic!("{scheme:?}: {e}"));

        // a signature over the digest of the delegation payload must not verify
        use sha2::{Digest as _, Sha512_256};
        let digest = Sha512_256::digest(delegation.to_be_signed());
        let over_digest = f.signer.sign_bytes(&digest);
        assert_ne!(over_digest, raw, "{scheme:?}");
        stx.lsig.as_mut().unwrap().pqsig.as_mut().unwrap().signature = ByteBuf::from(over_digest);
        let e = verify(&stx, &future_proto()).unwrap_err();
        assert!(e.contains(invalid_text(scheme)), "{scheme:?}: {e}");
    }
}

// go's `TestTxnGroupSaltedKeySigMixedSignatures`: a SaltedKeySig excludes every
// other kind of signature.
#[test]
fn txn_group_salted_key_sig_mixed_signatures() {
    let proto = future_proto();
    let base = |seed| sksig_txn(seed, *b"f1");

    let mut stx = base(4);
    stx.pqsig = Some(SaltedKeySig::default());
    let e = verify(&stx, &proto).unwrap_err();
    assert!(
        e.contains("signedtxn has no sig"),
        "empty sksig and no other signature: {e}"
    );

    let mut stx = base(5);
    stx.sig = [7u8; 64];
    let e = verify(&stx, &proto).unwrap_err();
    assert!(
        e.contains("signedtxn should have only one type of signature"),
        "sksig + sig: {e}"
    );

    let mut stx = base(6);
    stx.msig = Some(algo_types::MultisigSig {
        subsigs: vec![algo_types::MultisigSubsig {
            public_key: [1u8; 32],
            signature: [2u8; 64],
        }],
        ..Default::default()
    });
    let e = verify(&stx, &proto).unwrap_err();
    assert!(
        e.contains("signedtxn should have only one type of signature"),
        "sksig + msig: {e}"
    );

    let mut stx = base(7);
    stx.lsig = Some(LogicSig {
        logic: ByteBuf::from(algo_avm::assemble_string("int 1").unwrap().program),
        ..LogicSig::default()
    });
    let e = verify(&stx, &proto).unwrap_err();
    assert!(
        e.contains("signedtxn should have only one type of signature"),
        "sksig + lsig: {e}"
    );
}

// ---- the ls scheme (go's `TestTxnValidationLogicSigSaltedKeySig`, `...Budget`) ----

/// go's `makeSaltedLogicSigTxn`: the program stands in for the public key, its
/// encoded arguments for the signature, and the address commits to both the
/// scheme and the program.
fn ls_txn(source: &str, args: &[&[u8]]) -> SignedTransaction {
    let program = algo_avm::assemble_string(source)
        .expect("assembles")
        .program;
    let (salt, authorizer) = algo_types::canonical_address_salt(*b"ls", &program).expect("salt");
    let args: Vec<Option<Vec<u8>>> = args.iter().map(|a| Some(a.to_vec())).collect();
    SignedTransaction {
        txn: pay(authorizer, Address([1u8; 32])),
        pqsig: Some(SaltedKeySig {
            scheme: *b"ls",
            salt,
            public_key: ByteBuf::from(program),
            signature: ByteBuf::from(algo_codec::encode_logic_sig_args(&args)),
        }),
        ..Default::default()
    }
}

fn ls_proto() -> ConsensusParams {
    ConsensusParams {
        require_logic_sig_arg_access: true,
        logic_sig_version: 14,
        ..future_proto()
    }
}

#[test]
fn txn_validation_logic_sig_salted_key_sig() {
    let proto = ls_proto();
    // a program with no arguments authorizes on its own: its empty Signature is a
    // complete proof, not a missing one
    let stx = ls_txn("int 1", &[]);
    assert!(stx.pqsig.as_ref().unwrap().signature.is_empty());
    verify(&stx, &proto).unwrap();

    // the arguments reach the program's arg opcodes
    let src = "#pragma version 14
arg 0
byte \"open\"
==";
    let with_args = ls_txn(src, &[b"open"]);
    verify(&with_args, &proto).unwrap();

    // anyone may rewrite the arguments, since nothing signs them, but only the
    // ones the program accepts get it to approve
    let mut wrong = with_args.clone();
    wrong.pqsig.as_mut().unwrap().signature =
        ByteBuf::from(algo_codec::encode_logic_sig_args(&[Some(b"shut".to_vec())]));
    assert!(verify(&wrong, &proto)
        .unwrap_err()
        .contains("rejected by logic"));

    // the rule against unread arguments applies to ls arguments too, and the
    // padding does not change the transaction ID
    let mut padded = with_args.clone();
    padded.pqsig.as_mut().unwrap().signature = ByteBuf::from(algo_codec::encode_logic_sig_args(&[
        Some(b"open".to_vec()),
        Some(b"junk".to_vec()),
    ]));
    assert_eq!(
        algo_codec::compute_txn_id(&with_args.txn),
        algo_codec::compute_txn_id(&padded.txn)
    );
    assert!(verify(&padded, &proto)
        .unwrap_err()
        .contains("arg[1] of 2 was not accessed"));

    // an unread argument below the highest one read must be empty
    let skips_src = "#pragma version 14
arg 1
byte \"open\"
==";
    let mut skips = ls_txn(skips_src, &[b"", b"open"]);
    verify(&skips, &proto).unwrap();
    skips.pqsig.as_mut().unwrap().signature = ByteBuf::from(algo_codec::encode_logic_sig_args(&[
        Some(b"junk".to_vec()),
        Some(b"open".to_vec()),
    ]));
    assert!(verify(&skips, &proto)
        .unwrap_err()
        .contains("arg[0] of 2 was not accessed"));

    // a rejecting program authorizes nothing, though its address is right
    assert!(verify(&ls_txn("int 0", &[]), &proto)
        .unwrap_err()
        .contains("rejected by logic"));

    // the address commits to the program: another program cannot spend here
    let mut swapped = ls_txn("int 1", &[]);
    swapped.pqsig.as_mut().unwrap().public_key = ByteBuf::from(
        algo_avm::assemble_string(
            "int 1
int 1
&&",
        )
        .unwrap()
        .program,
    );
    assert!(verify(&swapped, &proto)
        .unwrap_err()
        .contains("authorizer mismatch"));

    // nor does the same program under a different salt
    let mut resalted = ls_txn("int 1", &[]);
    let sk = resalted.pqsig.as_mut().unwrap();
    sk.salt = AddressSalt(sk.salt.0.wrapping_add(1));
    assert!(verify(&resalted, &proto)
        .unwrap_err()
        .contains("authorizer mismatch"));

    // arguments must be canonically encoded: one set of arguments, one spelling
    let mut noncanonical = ls_txn("int 1", &[]);
    noncanonical.pqsig.as_mut().unwrap().signature = ByteBuf::from(vec![0x90]); // an empty array
    assert!(verify(&noncanonical, &proto)
        .unwrap_err()
        .contains("not canonically encoded"));

    // disabled where consensus has not enabled the scheme
    let disabled = disable(&proto, *b"ls");
    assert!(verify(&ls_txn("int 1", &[]), &disabled)
        .unwrap_err()
        .contains("not enabled"));
}

// go's `TestLogicSigSaltedKeySigBudget`: an ls program draws on the group's pooled
// LogicSig budget (the pool is the group's, whatever kind of proof a member has).
#[test]
fn logic_sig_salted_key_sig_budget_is_pooled_across_the_group() {
    let proto = ls_proto();
    let budget_txn = |cost: u64| {
        ls_txn(
            &format!(
                "#pragma version 6
global OpcodeBudget
int {cost}
=="
            ),
            &[],
        )
    };
    let run = |members: Vec<SignedTransaction>| -> Result<(), String> {
        let mut pool = GroupBudget::for_logicsig(members.len());
        for (i, stx) in members.iter().enumerate() {
            verify_transaction_signature(stx, &members, i, &mut pool, &proto)
                .map_err(validation_text)?;
        }
        Ok(())
    };
    // two members: the pool is twice LogicSigMaxCost less the global opcode; the
    // second program sees what the first left, three opcodes later
    let pooled = 2 * 20_000 - 1;
    run(vec![budget_txn(pooled), budget_txn(pooled - 3)]).unwrap();
    // without the pool each program would start from LogicSigMaxCost of its own
    let unpooled = 20_000 - 1;
    let mut second = budget_txn(unpooled);
    second.txn.note = ByteBuf::from(vec![1]);
    assert!(run(vec![budget_txn(unpooled), second])
        .unwrap_err()
        .contains("rejected by logic"));
}
