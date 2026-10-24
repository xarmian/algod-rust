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

//! Issue #2046: go's generated msgp decoders read `[N]byte` fields with
//! `msgp.ReadExactBytes` and `[]byte` fields with `msgp.ReadBytesBytes`
//! (algorand/msgp v1.1.64 `msgp/read_bytes.go`, "go-codec compat"), which
//! accept `str`, `nil` and uint8-array encodings and do not enforce the
//! array length. These end-to-end tests pin that algod-rust's raw decoders for
//! `SignedTransaction` and `BlockHeader` accept the same non-canonical
//! encodings and yield the same decoded struct as the canonical `bin` form.
//! Per-field evidence: `docs/BYTES_DECODE_PARITY.md`.

use algo_types::{BlockHeader, SignedTransaction};

fn fixstr(s: &str) -> Vec<u8> {
    assert!(s.len() < 32);
    let mut v = vec![0xa0 | s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

fn bin(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0xc4, b.len() as u8];
    v.extend_from_slice(b);
    v
}

fn strenc(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0xd9, b.len() as u8];
    v.extend_from_slice(b);
    v
}

fn map(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    assert!(entries.len() < 16);
    let mut v = vec![0x80 | entries.len() as u8];
    for (k, val) in entries {
        v.extend(fixstr(k));
        v.extend(val);
    }
    v
}

/// `{"sig": <sig>, "txn": {"type":"pay","snd":<snd>,"rcv":<rcv>,"note":<note>,"lx":<lx>,"amt":5}}`
fn stxn(sig: Vec<u8>, snd: Vec<u8>, rcv: Vec<u8>, note: Vec<u8>, lx: Vec<u8>) -> Vec<u8> {
    let txn = map(vec![
        ("type", fixstr("pay")),
        ("snd", snd),
        ("rcv", rcv),
        ("note", note),
        ("lx", lx),
        ("amt", vec![5]),
    ]);
    map(vec![("sig", sig), ("txn", txn)])
}

fn decode_stxn(b: &[u8]) -> Result<SignedTransaction, algo_error::AlgoError> {
    let mut rd = b;
    SignedTransaction::decode_from_reader(&mut rd)
}

#[test]
fn signed_txn_str_encoded_byte_fields_match_bin() {
    let snd = [1u8; 32];
    let rcv = [2u8; 32];
    let sig = [3u8; 64];
    let lx = [4u8; 32];
    let canonical = decode_stxn(&stxn(
        bin(&sig),
        bin(&snd),
        bin(&rcv),
        bin(b"hello"),
        bin(&lx),
    ))
    .unwrap();
    // every byte-typed field as `str` (go ReadExactBytes / ReadBytesBytes).
    let as_str = decode_stxn(&stxn(
        strenc(&sig),
        strenc(&snd),
        strenc(&rcv),
        strenc(b"hello"),
        strenc(&lx),
    ))
    .unwrap();
    assert_eq!(as_str.sig, sig);
    assert_eq!(as_str.txn.sender.0, snd);
    assert_eq!(as_str.txn.receiver.0, rcv);
    assert_eq!(as_str.txn.note.as_slice(), b"hello");
    assert_eq!(as_str.txn.lease, lx);
    assert_eq!(as_str, canonical);
}

#[test]
fn signed_txn_nil_byte_fields_decode_to_zero_like_go() {
    // go: ReadExactBytes(nil) zeroes the array; ReadBytesBytes(nil) -> empty.
    let d = decode_stxn(&stxn(
        vec![0xc0],
        bin(&[1u8; 32]),
        vec![0xc0],
        vec![0xc0],
        vec![0xc0],
    ))
    .unwrap();
    assert_eq!(d.sig, [0u8; 64]);
    assert!(d.txn.receiver.is_zero());
    assert!(d.txn.note.is_empty());
    assert_eq!(d.txn.lease, [0u8; 32]);
}

#[test]
fn signed_txn_wrong_length_fixed_fields_are_min_copied_like_go() {
    // ReadExactBytes copies min(encoded, N): a 31-byte `snd` is the address
    // with a zero last byte; a 33-byte `rcv` is truncated to 32.
    let mut snd31 = [7u8; 31].to_vec();
    let mut rcv33 = [8u8; 33].to_vec();
    rcv33[32] = 0xff;
    let d = decode_stxn(&stxn(
        bin(&[3u8; 64]),
        bin(&snd31),
        bin(&rcv33),
        bin(b""),
        bin(&[0u8; 32]),
    ))
    .unwrap();
    snd31.push(0);
    assert_eq!(d.txn.sender.0.to_vec(), snd31);
    assert_eq!(d.txn.receiver.0, [8u8; 32]);
}

#[test]
fn signed_txn_array_encoded_bytes_match_go() {
    // `[]byte` as an explicit array of uint8 (readBytesBytesSlow).
    let note = vec![0x93, 1, 2, 3];
    let d = decode_stxn(&stxn(
        bin(&[3u8; 64]),
        bin(&[1u8; 32]),
        bin(&[2u8; 32]),
        note,
        bin(&[0u8; 32]),
    ))
    .unwrap();
    assert_eq!(d.txn.note.as_slice(), &[1, 2, 3]);
}

#[test]
fn signed_txn_non_bytes_marker_still_rejected() {
    // go: badPrefix(BinType, lead) for an integer where bytes are expected.
    assert!(decode_stxn(&stxn(
        bin(&[3u8; 64]),
        bin(&[1u8; 32]),
        vec![0x05],
        bin(b""),
        bin(&[0u8; 32]),
    ))
    .is_err());
}

#[test]
fn block_header_str_and_nil_hash_fields_match_go() {
    let gh = [0x11u8; 32];
    let prev = [0x22u8; 32];
    let canonical = {
        let b = map(vec![
            ("rnd", vec![7]),
            ("gh", bin(&gh)),
            ("prev", bin(&prev)),
        ]);
        let mut rd = &b[..];
        BlockHeader::decode_from_reader(&mut rd).unwrap()
    };
    let b = map(vec![
        ("rnd", vec![7]),
        ("gh", strenc(&gh)),
        ("prev", strenc(&prev)),
    ]);
    let mut rd = &b[..];
    let as_str = BlockHeader::decode_from_reader(&mut rd).unwrap();
    assert_eq!(as_str.genesis_hash, gh);
    assert_eq!(as_str.branch, prev);
    assert_eq!(as_str, canonical);

    let b = map(vec![
        ("rnd", vec![7]),
        ("gh", vec![0xc0]),
        ("prev", vec![0xc0]),
    ]);
    let mut rd = &b[..];
    let nil = BlockHeader::decode_from_reader(&mut rd).unwrap();
    assert_eq!(nil.genesis_hash, [0u8; 32]);
    assert_eq!(nil.branch, [0u8; 32]);
}

#[test]
fn nil_string_fields_decode_as_empty_like_go() {
    // go ReadStringZC maps nil to "" for every generated `string` field.
    let b = map(vec![
        ("rnd", vec![7]),
        ("gen", vec![0xc0]),
        ("proto", vec![0xc0]),
    ]);
    let mut rd = &b[..];
    let h = BlockHeader::decode_from_reader(&mut rd).unwrap();
    assert_eq!(h.genesis_id, "");
    assert_eq!(h.current_protocol, "");
}
