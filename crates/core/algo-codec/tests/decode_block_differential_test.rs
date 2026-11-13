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

//! `decode_block` (hand-written reader behind the depth pre-scan) against
//! `decode_block_serde` (the derived-serde decoder it replaced), issue #2319.
//!
//! On every canonical block, on every truncation and on trailing bytes the two
//! must agree exactly. On mutated input they may differ, but only in the
//! classes below, each of which the hand reader (go-algorand's msgp decoder is
//! the reference) gets right and serde gets wrong or approximates; DIV-004
//! lists them. Any other disagreement fails this test.
//!
//! | class | serde | hand reader | go |
//! |---|---|---|---|
//! | A non-UTF-8 `str` key inside `state_proof_tracking` | turns it into `bin` (changes the canonical re-encode, so the block hash) | keeps the `str` bytes (#2042) | keeps the `str` bytes |
//! | B integer where a map key belongs | accepts, as a field index | rejects | rejects (`ReadMapKeyZC`) |
//! | C struct sent as an array (map header replaced) | accepts a degenerate array | rejects (DIV-004) | decodes positionally |
//! | D transaction without `type` | accepts | rejects at decode | decodes, fails later |
//! | E nil where an integer, boolean or struct belongs | rejects ("unit value") | zero value | zero value (DIV-004, #2065) |
//! | F `[N]byte` field of another length | rejects ("expected N bytes") | `ReadExactBytes`: copies `min(len, N)` bytes | same (`docs/BYTES_DECODE_PARITY.md`) |

use algo_codec::{decode_block, decode_block_serde};
use algo_types::Block;

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn fixtures() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for n in 1..=9 {
        let p = format!("tests/fixtures/block_{n}.msgpack");
        out.push((p.clone(), read(&p)));
    }
    for name in ["block-small.msgpack", "block-large.msgpack"] {
        let p = format!(
            "{}/../../../benchmarks/fixtures/micro/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        out.push((name.to_string(), read(&p)));
    }
    // Round 0 (the genesis block): go omits a zero `rnd`, and the hand reader
    // of the agreement codec used to require it.
    let genesis = Block {
        genesis_id: "test-v1".into(),
        genesis_hash: [7u8; 32],
        current_protocol: "future".into(),
        ..Block::default()
    };
    out.push(("round-0 block".into(), algo_codec::canonical_encode_block(&genesis)));
    out
}

#[derive(Debug, Default)]
struct Tally {
    both_ok: usize,
    both_err: usize,
    class_a: usize,
    class_b: usize,
    class_c: usize,
    class_d: usize,
    class_e: usize,
    class_f: usize,
}

/// Compare the two decoders on `bytes` (mutated at `at`, or `usize::MAX`).
/// Panics on a disagreement outside the documented classes.
fn compare(label: &str, bytes: &[u8], at: usize, t: &mut Tally) {
    let serde = decode_block_serde(bytes);
    let hand = decode_block(bytes);
    match (&serde, &hand) {
        (Ok(a), Ok(b)) if a == b => t.both_ok += 1,
        (Ok(a), Ok(b)) => {
            // Class A: the only difference is the `state_proof_tracking`
            // value (a non-UTF-8 str key).
            let (mut a, mut b) = (a.clone(), b.clone());
            a.state_proof_tracking = None;
            b.state_proof_tracking = None;
            assert_eq!(a, b, "{label}: both decode, to blocks that differ outside class A");
            t.class_a += 1;
        }
        (Err(_), Err(_)) => t.both_err += 1,
        (Ok(_), Err(e)) => {
            let msg = format!("{e:?}");
            if msg.contains("expected string marker") {
                t.class_b += 1;
            } else if at == 0 && msg.contains("read_map_len") {
                t.class_c += 1;
            } else if msg.contains("missing required field 'type'") {
                t.class_d += 1;
            } else {
                panic!("{label}: serde accepts, the hand reader rejects, outside the classes: {msg}");
            }
        }
        (Err(e), Ok(_)) => {
            let msg = format!("{e:?}");
            if at != usize::MAX && bytes[at] == 0xc0 && msg.contains("unit value") {
                t.class_e += 1;
            } else if at != usize::MAX && msg.contains("bytes, got") {
                t.class_f += 1;
            } else {
                panic!("{label}: the hand reader accepts, serde rejects, outside classes E and F: {msg}");
            }
        }
    }
}

#[test]
fn both_decoders_agree_exactly_on_every_canonical_block() {
    for (name, bytes) in fixtures() {
        let serde = decode_block_serde(&bytes).unwrap_or_else(|e| panic!("{name}: serde: {e}"));
        let hand = decode_block(&bytes).unwrap_or_else(|e| panic!("{name}: hand: {e}"));
        assert_eq!(serde, hand, "{name}");
        // And the canonical re-encode is the stored encoding.
        if name != "round-0 block" && !name.contains("block_") {
            assert_eq!(algo_codec::canonical_encode_block(&hand), bytes, "{name}");
        }
    }
}

/// Every proper prefix of a block is truncated input: both reject it.
#[test]
fn both_decoders_reject_every_truncation_of_small_blocks() {
    for (name, bytes) in fixtures().into_iter().filter(|(_, b)| b.len() < 4000) {
        for cut in 0..bytes.len() {
            let (s, h) = (decode_block_serde(&bytes[..cut]), decode_block(&bytes[..cut]));
            assert_eq!(
                s.is_ok(),
                h.is_ok(),
                "{name} cut at {cut}: serde {:?}, hand {:?}",
                s.as_ref().err(),
                h.as_ref().err()
            );
        }
    }
}

/// One byte replaced by a value that changes a marker, a length or a type.
#[test]
fn single_byte_substitutions_differ_only_in_the_documented_classes() {
    const SUBS: [u8; 12] = [
        0x00, 0x01, 0x7f, 0x80, 0x90, 0xa0, 0xc0, 0xc1, 0xc4, 0xcc, 0xdf, 0xff,
    ];
    let mut t = Tally::default();
    for (name, bytes) in fixtures().into_iter().filter(|(_, b)| b.len() < 4000) {
        for at in 0..bytes.len() {
            for sub in SUBS {
                if bytes[at] == sub {
                    continue;
                }
                let mut m = bytes.clone();
                m[at] = sub;
                compare(&format!("{name} byte {at} = {sub:#04x}"), &m, at, &mut t);
            }
        }
    }
    eprintln!("{t:?}");
    assert!(t.both_ok > 20_000 && t.both_err > 1_000, "{t:?}");
    // Each class really occurs, so the assertions above are not vacuous.
    assert!(
        t.class_a > 0 && t.class_b > 0 && t.class_c > 0 && t.class_e > 0 && t.class_f > 0,
        "{t:?}"
    );
}

/// Trailing bytes after a complete block.
#[test]
fn trailing_bytes_are_treated_alike() {
    for (name, bytes) in fixtures().into_iter().filter(|(_, b)| b.len() < 4000) {
        for tail in [&[0u8][..], &[0xc0], &[0x80], &[0x01, 0x02, 0x03]] {
            let mut m = bytes.clone();
            m.extend_from_slice(tail);
            let (s, h) = (decode_block_serde(&m), decode_block(&m));
            assert_eq!(s.is_ok(), h.is_ok(), "{name} + {tail:02x?}");
            if let (Ok(s), Ok(h)) = (s, h) {
                assert_eq!(s, h, "{name} + {tail:02x?}");
            }
        }
    }
}

/// A sample of mutations of the large block (218 KB: too many to try all).
#[test]
fn sampled_mutations_of_the_large_block_differ_only_in_the_documented_classes() {
    let (name, bytes) = fixtures()
        .into_iter()
        .find(|(n, _)| n == "block-large.msgpack")
        .unwrap();
    let mut state = 0x2319_2319_2319_2319u64;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut t = Tally::default();
    for _ in 0..3_000 {
        let at = (next() % bytes.len() as u64) as usize;
        let sub = [0x00u8, 0x7f, 0x90, 0xc0, 0xc1, 0xc4, 0xde, 0xff][(next() % 8) as usize];
        let mut m = bytes.clone();
        m[at] = sub;
        compare(&format!("{name} byte {at} = {sub:#04x}"), &m, at, &mut t);
    }
    for _ in 0..200 {
        let cut = (next() % bytes.len() as u64) as usize;
        assert!(decode_block_serde(&bytes[..cut]).is_err(), "{name} cut {cut}");
        assert!(decode_block(&bytes[..cut]).is_err(), "{name} cut {cut}");
    }
    eprintln!("{t:?}");
    assert!(t.both_ok + t.both_err > 2_000, "{t:?}");
}

/// The depth bound of the pre-scan holds for the new `decode_block`: a deeply
/// nested unknown field is refused at exactly the depth it was before.
#[test]
fn the_depth_bound_is_unchanged() {
    for depth in [10usize, 200, 253, 254, 255, 256, 300, 5_000] {
        // {"zzz": [[[...[0]...]]]}: a block map with one unknown key.
        let mut m = vec![0x81, 0xa3, b'z', b'z', b'z'];
        m.extend(std::iter::repeat_n(0x91u8, depth));
        m.push(0x00);
        assert_eq!(
            decode_block_serde(&m).is_ok(),
            decode_block(&m).is_ok(),
            "depth {depth}"
        );
    }
}
