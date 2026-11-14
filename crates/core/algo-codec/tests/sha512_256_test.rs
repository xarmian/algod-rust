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

//! `algo_codec::hash` (ring) against NIST vectors generated with go's
//! `crypto/sha512.Sum512_256` and against `sha2::Sha512_256` (issue #2321).

use algo_codec::hash::{sha512_256, Sha512_256Hasher};
use sha2::Digest as _;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn reference(data: &[u8]) -> [u8; 32] {
    sha2::Sha512_256::digest(data).into()
}

/// Vectors produced by go's standard library (`sha512.Sum512_256`); the
/// "abc", 896-bit and one-million-`a` messages are the FIPS 180-4 examples.
#[test]
fn matches_go_on_the_nist_vectors() {
    let nist896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "empty",
            vec![],
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        ),
        (
            "abc",
            b"abc".to_vec(),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        ),
        (
            "nist896",
            nist896.as_bytes().to_vec(),
            "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a",
        ),
        (
            "a111",
            vec![b'a'; 111],
            "0239e429f98d0ed61ee8e2a7c30afe98c1c3a80ce5dff62a107e9c538f7632ce",
        ),
        (
            "a112",
            vec![b'a'; 112],
            "9216b5303edb66504570bee90e48ea5beaa5e9fe9f760bbd3e0460559fc005f6",
        ),
        (
            "a128",
            vec![b'a'; 128],
            "b88f97e274f9c1d49f181c8cbd01a9c74930ad055a46ac4499a1d601f1c80bf2",
        ),
        (
            "a1000",
            vec![b'a'; 1000],
            "40eb4a70d4d69815407a9e272f0101cd67e3d11262a4a0bfc087712749c7fb53",
        ),
        (
            "million",
            vec![b'a'; 1_000_000],
            "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
        ),
    ];
    for (name, data, want) in cases {
        assert_eq!(hex(&sha512_256(&[&data])), want, "{name}");
    }
}

/// Every length up to 4,500 bytes (past 35 SHA-512 blocks), on pseudo-random
/// data, against `sha2`.
#[test]
fn equals_sha2_for_every_length_up_to_4500() {
    let mut x = 0x2321_2321_2321_2321u64;
    let data: Vec<u8> = (0..4500)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    for n in 0..=data.len() {
        assert_eq!(sha512_256(&[&data[..n]]), reference(&data[..n]), "len {n}");
    }
}

/// The block boundaries of long inputs (the padding is where an
/// implementation differs).
#[test]
fn equals_sha2_around_the_block_boundaries_of_long_inputs() {
    let data: Vec<u8> = (0..70_000u32).map(|i| (i * 31 + 7) as u8).collect();
    for base in [4096usize, 8192, 32_768, 65_536] {
        for delta in 0..=130 {
            let n = (base + delta).min(data.len());
            assert_eq!(sha512_256(&[&data[..n]]), reference(&data[..n]), "len {n}");
            let m = base.saturating_sub(delta);
            assert_eq!(sha512_256(&[&data[..m]]), reference(&data[..m]), "len {m}");
        }
    }
}

/// Splitting the input anywhere, in any number of parts, changes nothing; the
/// incremental hasher agrees.
#[test]
fn parts_and_the_incremental_hasher_equal_the_concatenation() {
    let data: Vec<u8> = (0..700u32).map(|i| (i * 13 + 5) as u8).collect();
    let whole = reference(&data);
    for cut in 0..=data.len() {
        let (a, b) = data.split_at(cut);
        assert_eq!(sha512_256(&[a, b]), whole, "two parts, cut {cut}");
        let mut h = Sha512_256Hasher::new();
        h.update(a);
        h.update(b);
        assert_eq!(h.finalize(), whole, "incremental, cut {cut}");
    }
    // Three parts straddling the 128-byte block boundary, and empty parts.
    assert_eq!(
        sha512_256(&[&data[..100], &[], &data[100..130], &data[130..]]),
        whole
    );
    assert_eq!(sha512_256(&[]), reference(b""));
    assert_eq!(Sha512_256Hasher::default().finalize(), reference(b""));
}

/// The domain-separated shape every consensus hash uses: prefix then data.
#[test]
fn prefix_then_data_equals_sha2_over_the_concatenation() {
    for prefix in [&b"TX"[..], b"BH", b"TG", b"MA", b"TL", b"STIB"] {
        for len in [0usize, 1, 31, 32, 33, 100, 111, 112, 200, 1000] {
            let data = vec![0xa5u8; len];
            let mut cat = prefix.to_vec();
            cat.extend_from_slice(&data);
            assert_eq!(sha512_256(&[prefix, &data]), reference(&cat));
        }
    }
}
