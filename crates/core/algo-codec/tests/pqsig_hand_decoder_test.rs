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

//! The hand-written msgpack decoders (`SignedTransaction::decode_from_reader`,
//! `LogicSig::decode_from_reader`) used by `POST /v2/transactions` must keep
//! the `pqsig` envelope that go-algorand's `algokey pq sign` /
//! `sign-program` write (issue #1960). Before the fix the key fell into
//! `skip_value`, so every PQ-account transaction submitted over REST looked
//! unsigned. The serde decoder (used for blocks and gossip) is the oracle.

use std::fs;
use std::path::PathBuf;

use algo_codec::{canonical_encode_logicsig, canonical_encode_signed_transaction};
use algo_types::{LogicSig, SignedTransaction};

fn load_hex_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pqsig")
        .join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    hex::decode(raw.trim()).unwrap_or_else(|e| panic!("invalid hex in {}: {e}", path.display()))
}

fn check_signed_txn_fixture(name: &str) {
    let bytes = load_hex_fixture(name);
    let oracle: SignedTransaction = rmp_serde::from_slice(&bytes).expect("serde decode");
    let hand = SignedTransaction::decode_from_bytes(&bytes).expect("hand decode");

    let pq = hand.pqsig.as_ref().unwrap_or_else(|| {
        panic!("{name}: the hand decoder dropped pqsig, so the txn would look unsigned")
    });
    assert!(!pq.blank(), "{name}: pqsig decoded blank");
    assert_eq!(hand, oracle, "{name}: hand decoder disagrees with serde");
    assert_eq!(
        hex::encode(canonical_encode_signed_transaction(&hand)),
        hex::encode(&bytes),
        "{name}: hand-decoded txn does not re-encode byte-identically"
    );
}

#[test]
fn hand_decoder_keeps_pqsig_when_authaddr_differs_from_the_signer() {
    check_signed_txn_fixture("signed_txn_with_pqsig.canonical.hex");
}

/// The live-workload shape: the sender IS the PQ address (no `sgnr`), signed
/// by go-algorand v5.0.4-stable `algokey pq sign`.
#[test]
fn hand_decoder_keeps_pqsig_when_the_sender_is_the_pq_address() {
    check_signed_txn_fixture("signed_txn_pq_sender_is_signer.canonical.hex");
}

#[test]
fn hand_decoder_keeps_the_logicsig_pqsig() {
    let bytes = load_hex_fixture("logicsig_with_pqsig.canonical.hex");
    let oracle: LogicSig = rmp_serde::from_slice(&bytes).expect("serde decode");
    let hand = LogicSig::decode_from_bytes(&bytes).expect("hand decode");
    assert!(
        hand.pqsig.as_ref().is_some_and(|p| !p.blank()),
        "the hand decoder dropped the delegated lsig pqsig"
    );
    assert_eq!(hand, oracle);
    assert_eq!(
        hex::encode(canonical_encode_logicsig(&hand)),
        hex::encode(&bytes)
    );
}

/// Every field of the envelope survives, including a non-zero salt (the Go
/// fixtures all use salt 0, which is omitted on the wire).
#[test]
fn hand_decoder_keeps_every_pqsig_field_including_a_non_zero_salt() {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = algo_types::Address([1u8; 32]);
    stx.pqsig = Some(algo_types::PQSig {
        scheme: *b"f1",
        salt: algo_types::PQAddressSalt(7),
        public_key: serde_bytes::ByteBuf::from(vec![0xAA; 33]),
        signature: serde_bytes::ByteBuf::from(vec![0xBB; 65]),
    });
    let bytes = canonical_encode_signed_transaction(&stx);
    let oracle: SignedTransaction = rmp_serde::from_slice(&bytes).expect("serde decode");
    let hand = SignedTransaction::decode_from_bytes(&bytes).expect("hand decode");
    assert_eq!(hand.pqsig, stx.pqsig);
    assert_eq!(hand, oracle);
}

/// A pqsig map with an extra key: the known fields are still decoded (the
/// sibling hand decoders skip unknown keys too; see the follow-up issue
/// about go rejecting unknown fields on submit).
#[test]
fn hand_decoder_pqsig_decodes_known_fields_next_to_an_unknown_key() {
    let mut raw: Vec<u8> = vec![0x85];
    raw.extend_from_slice(b"\xa3sch\xc4\x02f1");
    raw.extend_from_slice(b"\xa3slt\x03");
    raw.extend_from_slice(b"\xa2pk\xc4\x02\x01\x02");
    raw.extend_from_slice(b"\xa3sig\xc4\x01\x09");
    raw.extend_from_slice(b"\xa3zzz\x01");
    let mut rd: &[u8] = &raw;
    let pq = algo_types::PQSig::decode_from_reader(&mut rd).expect("decode");
    assert!(rd.is_empty());
    assert_eq!(pq.scheme, *b"f1");
    assert_eq!(pq.salt, algo_types::PQAddressSalt(3));
    assert_eq!(pq.public_key.as_slice(), &[1u8, 2]);
    assert_eq!(pq.signature.as_slice(), &[9u8]);
}
