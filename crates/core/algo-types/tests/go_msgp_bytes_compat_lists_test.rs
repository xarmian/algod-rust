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

//! Issue #2046 review follow-ups (PR #2062): nil elements inside go
//! `[][]byte` lists (corrected by issue #2430: go keeps them nil), str-form
//! decode of the nested LogicSig / Msig / Heartbeat / StateProof / Falcon
//! structs, and canonical re-encode equality. See `docs/BYTES_DECODE_PARITY.md`.

use algo_types::{
    FalconVerifier, HeartbeatTxnFields, LogicSig, MerkleProof, MultisigSig, SignedTransaction,
    StateProofMessage,
};

fn fixstr(s: &str) -> Vec<u8> {
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
    let mut v = vec![0x80 | entries.len() as u8];
    for (k, val) in entries {
        v.extend(fixstr(k));
        v.extend(val);
    }
    v
}

fn arr(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = vec![0x90 | items.len() as u8];
    for i in items {
        v.extend(i);
    }
    v
}

fn appl(extra: Vec<(&str, Vec<u8>)>, snd: Vec<u8>, sig: Vec<u8>) -> Vec<u8> {
    let mut entries = vec![("type", fixstr("appl")), ("snd", snd)];
    entries.extend(extra);
    map(vec![("sig", sig), ("txn", map(entries))])
}

fn dec(b: &[u8]) -> SignedTransaction {
    SignedTransaction::decode_from_reader(&mut &b[..]).unwrap()
}

fn reencode(s: &SignedTransaction) -> Vec<u8> {
    rmp_serde::to_vec_named(s).unwrap()
}

#[test]
fn nil_list_elements_stay_nil_and_empty_ones_reencode_as_bin0() {
    // go `msgp.ReadBytesBytes` keeps a nil element nil (`AppendBytes` writes
    // `nil`); a `bin` / `str` of length 0 is a non-nil empty slice (`bin` 0).
    // Issue #2430, read with the strict-decode oracle.
    let empty_elem = dec(&appl(
        vec![("apaa", arr(vec![bin(b"x"), bin(b""), bin(b"y")]))],
        bin(&[1u8; 32]),
        bin(&[3u8; 64]),
    ));
    let nil_elem = dec(&appl(
        vec![("apaa", arr(vec![bin(b"x"), vec![0xc0], strenc(b"y")]))],
        bin(&[1u8; 32]),
        bin(&[3u8; 64]),
    ));
    assert_ne!(nil_elem, empty_elem);
    let args = nil_elem.txn.app_arguments.as_ref().unwrap();
    assert_eq!(args[1], None);
    let args = empty_elem.txn.app_arguments.as_ref().unwrap();
    assert_eq!(args[1].as_ref().map(|a| a.len()), Some(0));
    let nil_enc = algo_types::canonical::canonical_encode_transaction(&nil_elem.txn);
    let empty_enc = algo_types::canonical::canonical_encode_transaction(&empty_elem.txn);
    // a4 "apaa" 93 c4 01 'x' <elem> c4 01 'y'
    let apaa = |elem: &[u8]| [&b"\xa4apaa\x93\xc4\x01x"[..], elem, b"\xc4\x01y"].concat();
    let has = |enc: &[u8], want: &[u8]| enc.windows(want.len()).any(|w| w == want);
    assert!(
        has(&nil_enc, &apaa(&[0xc0])),
        "nil element re-encodes as nil"
    );
    assert!(
        has(&empty_enc, &apaa(&[0xc4, 0x00])),
        "empty element as bin0"
    );
    // the derived serde encoder agrees
    assert!(has(&reencode(&nil_elem), &[0x93, 0xc4, 0x01, b'x', 0xc0]));
}

#[test]
fn merkle_proof_nil_path_element_stays_nil() {
    let m = map(vec![(
        "pth",
        arr(vec![bin(&[1u8; 32]), vec![0xc0], fixstr("")]),
    )]);
    let p = MerkleProof::decode_from_reader(&mut &m[..]).unwrap();
    let path = p.path.unwrap();
    assert_eq!(path.len(), 3);
    assert_eq!(path[1], None);
    assert_eq!(path[2].as_ref().map(|d| d.len()), Some(0));
}

#[test]
fn logicsig_nil_arg_stays_nil_and_reencodes_as_nil() {
    let m = map(vec![
        ("arg", arr(vec![vec![0xc0], bin(b""), bin(b"b")])),
        ("l", bin(&[1, 32, 1, 1, 34])),
    ]);
    let l = LogicSig::decode_from_bytes(&m).unwrap();
    let args = l.args.as_ref().unwrap();
    assert_eq!(args[0], None);
    assert_eq!(args[1].as_ref().map(|a| a.len()), Some(0));
    // go's `protocol.Encode` of the decoded LogicSig: `arg` [nil, bin0, "b"]
    assert_eq!(
        algo_types::canonical::canonical_encode_logicsig(&l),
        hex_bytes("82a361726793c0c400c40162a16cc4050120010122")
    );
    // what a program sees (`arg 0`, size checks): a zero-length value
    assert_eq!(
        l.arg_bytes().collect::<Vec<_>>(),
        vec![&b""[..], &b""[..], &b"b"[..]]
    );
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn box_names_and_app_args_in_str_form_match_bin_form() {
    let a = dec(&appl(
        vec![
            (
                "apbx",
                arr(vec![map(vec![("i", vec![1]), ("n", bin(b"bx"))])]),
            ),
            ("apaa", arr(vec![bin(b"z")])),
        ],
        bin(&[1u8; 32]),
        bin(&[3u8; 64]),
    ));
    let b = dec(&appl(
        vec![
            (
                "apbx",
                arr(vec![map(vec![("i", vec![1]), ("n", strenc(b"bx"))])]),
            ),
            ("apaa", arr(vec![strenc(b"z")])),
        ],
        strenc(&[1u8; 32]),
        strenc(&[3u8; 64]),
    ));
    assert_eq!(a, b);
    assert_eq!(reencode(&a), reencode(&b));
}

#[test]
fn nested_structs_decode_identically_from_str_and_bin() {
    let ls = |b: fn(&[u8]) -> Vec<u8>| {
        let m = map(vec![
            ("l", b(&[0x06, 0x81, 0x01])),
            ("sig", b(&[9u8; 64])),
            ("arg", arr(vec![b(b"a"), vec![0xc0]])),
        ]);
        LogicSig::decode_from_reader(&mut &m[..]).unwrap()
    };
    assert_eq!(ls(strenc), ls(bin));

    let ms = |b: fn(&[u8]) -> Vec<u8>| {
        let sub = map(vec![("pk", b(&[5u8; 32])), ("s", b(&[6u8; 64]))]);
        let m = map(vec![
            ("v", vec![1]),
            ("thr", vec![1]),
            ("subsig", arr(vec![sub])),
        ]);
        MultisigSig::decode_from_reader(&mut &m[..]).unwrap()
    };
    assert_eq!(ms(strenc), ms(bin));

    let hb = |b: fn(&[u8]) -> Vec<u8>| {
        let prf = map(vec![
            ("s", b(&[1u8; 64])),
            ("p", b(&[2u8; 32])),
            ("p2", b(&[3u8; 32])),
            ("p1s", b(&[4u8; 64])),
            ("p2s", b(&[5u8; 64])),
        ]);
        let m = map(vec![
            ("a", b(&[7u8; 32])),
            ("prf", prf),
            ("sd", b(&[8u8; 32])),
            ("vid", b(&[9u8; 32])),
        ]);
        HeartbeatTxnFields::decode_from_reader(&mut &m[..]).unwrap()
    };
    assert_eq!(hb(strenc), hb(bin));

    let sp = |b: fn(&[u8]) -> Vec<u8>| {
        let m = map(vec![("b", b(&[1u8; 32])), ("v", b(&[2u8; 32]))]);
        StateProofMessage::decode_from_reader(&mut &m[..]).unwrap()
    };
    assert_eq!(sp(strenc), sp(bin));
}

#[test]
fn falcon_public_key_is_normalised_to_the_go_array_size() {
    let fv = |v: Vec<u8>| {
        let m = map(vec![("k", v)]);
        FalconVerifier::decode_from_reader(&mut &m[..]).unwrap()
    };
    let mut short = vec![0xc5, 0, 100];
    short.extend([0x42u8; 100]);
    let k = fv(short).public_key;
    assert_eq!(k.len(), 1793);
    assert!(k[..100].iter().all(|&b| b == 0x42) && k[100..].iter().all(|&b| b == 0));
    assert!(fv(vec![0xc0]).public_key.is_empty(), "zero value");
    let mut long = vec![0xc5, 0x07, 0x08]; // 1800 bytes
    long.extend(vec![0x11u8; 0x708]);
    assert_eq!(fv(long).public_key.len(), 1793);
}
