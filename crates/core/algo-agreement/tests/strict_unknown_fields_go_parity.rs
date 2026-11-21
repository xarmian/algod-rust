// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict unknown-field and repeated-key parity with go-algorand (issues
//! #2394, #2424).
//!
//! go decodes every msgpack message with generated msgp decoders, where a key
//! the target struct lacks is `msgp.ErrNoField` and the message is dropped
//! (`protocol.CodecHandle.ErrorIfNoField = true` on the reflection path), and a
//! key that occurs twice is decoded again INTO the already decoded field (a
//! nested struct is merged, a slice is re-sliced within its capacity, a
//! `[N]byte` keeps the bytes past a shorter value). `tests/fixtures/strict_decode/`
//! holds valid messages (`seeds.jsonl`, real blocks/votes plus go-encoded fully
//! populated random objects) and mutants of them with go's accept/reject
//! verdict and, for an accepted one, the sha256 prefix of go's re-encode of
//! what it decoded (`cases.jsonl`), produced by
//! `scripts/strict-decode/strict_decode_fixtures.py` running go's real decoders
//! (tools/strict-decode-oracle). Every entry point of algod-rust that reads
//! one of those message kinds must give the same verdict on every case and
//! decode the same value: each decoded value is re-encoded with the node's own
//! go-canonical encoder and compared with go's.
//!
//! The mutator is `scripts/strict-decode/replay.rs` (shared with the
//! non-consensus parity tests); the fixture's `sha` pins that it and the
//! script's produce the same bytes.

use std::collections::BTreeMap;

use algo_agreement::codec::{
    decode_bundle, decode_compound_message, decode_vote, encode_bundle, encode_compound_message,
    encode_vote,
};
use algo_types::{BlockHeader, BlockResponse, SignedTransaction, Transaction};

#[path = "../../../../scripts/strict-decode/replay.rs"]
mod replay;

use replay::{valued, Verdicts};

// ── raw msgpack walking (for the apply-data wrapper) ─────────────────────

fn be(b: &[u8], i: usize, n: usize) -> usize {
    b[i..i + n]
        .iter()
        .fold(0usize, |a, &x| (a << 8) | x as usize)
}

fn skip(b: &[u8], i: usize) -> usize {
    let c = b[i];
    match c {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => i + 1,
        0x80..=0x8f => skip_n(b, i + 1, 2 * (c & 0x0f) as usize),
        0x90..=0x9f => skip_n(b, i + 1, (c & 0x0f) as usize),
        0xa0..=0xbf => i + 1 + (c & 0x1f) as usize,
        0xcc | 0xd0 => i + 2,
        0xcd | 0xd1 => i + 3,
        0xce | 0xd2 | 0xca => i + 5,
        0xcf | 0xd3 | 0xcb => i + 9,
        0xc4 | 0xd9 => i + 2 + b[i + 1] as usize,
        0xc5 | 0xda => i + 3 + be(b, i + 1, 2),
        0xc6 | 0xdb => i + 5 + be(b, i + 1, 4),
        0xdc => skip_n(b, i + 3, be(b, i + 1, 2)),
        0xdd => skip_n(b, i + 5, be(b, i + 1, 4)),
        0xde => skip_n(b, i + 3, 2 * be(b, i + 1, 2)),
        0xdf => skip_n(b, i + 5, 2 * be(b, i + 1, 4)),
        _ => panic!("unsupported msgpack byte {c:#x}"),
    }
}

fn skip_n(b: &[u8], mut i: usize, n: usize) -> usize {
    for _ in 0..n {
        i = skip(b, i);
    }
    i
}

/// (header length, entry count) of the map at the start of `b`, if it is one.
fn map_header(b: &[u8]) -> Option<(usize, usize)> {
    match b[0] {
        c @ 0x80..=0x8f => Some((1, (c & 0x0f) as usize)),
        0xde => Some((3, be(b, 1, 2))),
        0xdf => Some((5, be(b, 1, 4))),
        _ => None,
    }
}

/// The top-level `(key, whole entry)` byte ranges of the map `b`.
fn entries(b: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let (hl, n) = map_header(b)?;
    let mut out = Vec::with_capacity(n);
    let mut j = hl;
    for _ in 0..n {
        let vs = skip(b, j);
        let ve = skip(b, vs);
        out.push((&b[j..vs], &b[j..ve]));
        j = ve;
    }
    Some(out)
}

/// The elements of the array at the start of `b`, if it is one.
fn array_items(b: &[u8]) -> Option<Vec<&[u8]>> {
    let (mut j, n) = match b[0] {
        c @ 0x90..=0x9f => (1, (c & 0x0f) as usize),
        0xdc => (3, be(b, 1, 2)),
        0xdd => (5, be(b, 1, 4)),
        _ => return None,
    };
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let e = skip(b, j);
        out.push(&b[j..e]);
        j = e;
    }
    Some(out)
}

fn map_len_header(n: usize) -> Vec<u8> {
    if n < 16 {
        vec![0x80 | n as u8]
    } else {
        let mut v = vec![0xde];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    }
}

// ── the entry points under test ───────────────────────────────────────────

const APPLY_DATA_KEYS: [&[u8]; 8] = [b"ca", b"dt", b"rs", b"rr", b"rc", b"aca", b"apid", b"caid"];
/// go's `ApplyData` fields in declaration (positional) order.
const APPLY_DATA_ORDER: [&[u8]; 8] = [b"ca", b"aca", b"rs", b"rr", b"rc", b"dt", b"caid", b"apid"];

/// `applydata` / `evaldelta` have no standalone reader in algod-rust (they
/// only occur inside a block's `SignedTxnInBlock`): embed the value in a
/// minimal valid signed transaction and decode that. go's `ApplyData` has
/// exactly the eight keys above, so a key outside them is rejected here.
fn wrap_in_stxn(kind: &str, b: &[u8], txn: &[u8]) -> Option<Vec<u8>> {
    let mut stxn = Vec::new();
    if kind == "evaldelta" {
        stxn.extend(map_len_header(2));
        stxn.extend_from_slice(b"\xa3txn");
        stxn.extend_from_slice(txn);
        stxn.extend_from_slice(b"\xa2dt");
        stxn.extend_from_slice(b);
        return Some(stxn);
    }
    if let Some(fields) = array_items(b) {
        // go's `ApplyData` as an array (issue #2426): element `i` is field
        // `i` of go's order (`APPLY_DATA_ORDER`); one past the eighth is go's
        // `ErrTooManyArrayFields`. The same fields as map entries.
        if fields.len() > APPLY_DATA_ORDER.len() {
            return None;
        }
        stxn.extend(map_len_header(fields.len() + 1));
        stxn.extend_from_slice(b"\xa3txn");
        stxn.extend_from_slice(txn);
        for (key, f) in APPLY_DATA_ORDER.iter().zip(fields) {
            stxn.push(0xa0 | key.len() as u8);
            stxn.extend_from_slice(key);
            stxn.extend_from_slice(f);
        }
        return Some(stxn);
    }
    let ad = entries(b)?;
    for (key, _) in &ad {
        // fixstr key
        if key.is_empty() || key[0] & 0xe0 != 0xa0 || !APPLY_DATA_KEYS.contains(&&key[1..]) {
            return None;
        }
    }
    stxn.extend(map_len_header(ad.len() + 1));
    stxn.extend_from_slice(b"\xa3txn");
    stxn.extend_from_slice(txn);
    for (_, e) in ad {
        stxn.extend_from_slice(e);
    }
    Some(stxn)
}

/// go's encoding of the `ApplyData` (or, for `evaldelta`, the `EvalDelta`) of
/// a wrapped transaction: its `SignedTxnInBlock` re-encode without the `txn`.
fn apply_data_part(kind: &str, stxib: &[u8]) -> Vec<u8> {
    let es = entries(stxib).expect("a SignedTxnInBlock is a map");
    if kind == "evaldelta" {
        return match es.iter().find(|(k, _)| *k == b"\xa2dt") {
            Some((k, e)) => e[k.len()..].to_vec(),
            // go's zero EvalDelta
            None => vec![0x80],
        };
    }
    let kept: Vec<_> = es.iter().filter(|(k, _)| *k != b"\xa3txn").collect();
    let mut out = map_len_header(kept.len());
    for (_, e) in kept {
        out.extend_from_slice(e);
    }
    out
}

/// go's `Certificate` encoding of a block response's opaque `cert`, as the
/// node reads it (`fetched_certificate`: re-encode, then `decode_bundle`).
fn encode_cert(cert: &Option<rmpv::Value>) -> Vec<u8> {
    let Some(v) = cert else {
        // go's zero Certificate
        return vec![0x80];
    };
    let mut raw = Vec::new();
    rmpv::encode::write_value(&mut raw, v).expect("encode cert");
    match decode_bundle(&raw) {
        Ok(b) => encode_bundle(&b),
        // the block response accepted a cert the bundle decoder rejects:
        // a value no go encoding matches
        Err(e) => format!("cert does not decode: {e}").into_bytes(),
    }
}

/// go's `EncodedBlockCert` encoding.
fn encode_block_response(r: &BlockResponse) -> Vec<u8> {
    let mut out = b"\x82\xa5block".to_vec();
    out.extend(algo_codec::canonical_encode_block(&r.block));
    out.extend_from_slice(b"\xa4cert");
    out.extend(encode_cert(&r.cert));
    out
}

fn rust_verdicts(kind: &str, b: &[u8], txn: &[u8]) -> Verdicts {
    match kind {
        "payload" => vec![(
            "decode_compound_message",
            valued(decode_compound_message(b), encode_compound_message),
        )],
        "vote" => vec![("decode_vote", valued(decode_vote(b), encode_vote))],
        "bundle" | "cert" => vec![("decode_bundle", valued(decode_bundle(b), encode_bundle))],
        "blockcert" => vec![
            (
                "decode_block_response",
                valued(algo_codec::decode_block_response(b), encode_block_response),
            ),
            (
                "decode_block_response_fast",
                valued(
                    algo_codec::decode_block_response_fast(b),
                    encode_block_response,
                ),
            ),
        ],
        "block" => vec![
            (
                "decode_block",
                valued(
                    algo_codec::decode_block(b),
                    algo_codec::canonical_encode_block,
                ),
            ),
            (
                "decode_block_fast",
                valued(
                    algo_codec::decode_block_fast(b),
                    algo_codec::canonical_encode_block,
                ),
            ),
        ],
        "header" => vec![(
            "BlockHeader::decode_from_bytes",
            valued(
                BlockHeader::decode_from_bytes(b),
                algo_codec::canonical_encode_block_header,
            ),
        )],
        "stxn" => {
            let _g = algo_types::strict_unknown_fields(b);
            vec![(
                "SignedTransaction (strict guard)",
                valued(
                    SignedTransaction::decode_from_bytes(b),
                    algo_codec::canonical_encode_signed_transaction,
                ),
            )]
        }
        "stxninblock" => vec![(
            "SignedTransaction (block)",
            valued(
                SignedTransaction::decode_from_bytes(b),
                algo_codec::canonical_encode_signed_txn_in_block,
            ),
        )],
        "txn" => vec![(
            "Transaction::decode_from_bytes",
            valued(
                Transaction::decode_from_bytes(b),
                algo_codec::canonical_encode_transaction,
            ),
        )],
        "applydata" | "evaldelta" => match wrap_in_stxn(kind, b, txn) {
            Some(w) => vec![(
                "SignedTransaction (block, wrapped)",
                valued(SignedTransaction::decode_from_bytes(&w), |s| {
                    apply_data_part(kind, &algo_codec::canonical_encode_signed_txn_in_block(s))
                }),
            )],
            None => vec![(
                "(top-level key outside ApplyData)",
                Err("top-level key outside ApplyData".into()),
            )],
        },
        other => panic!("unknown kind {other}"),
    }
}

fn seeds() -> BTreeMap<String, Vec<u8>> {
    replay::rows(&replay::fixture(env!("CARGO_MANIFEST_DIR"), "seeds.jsonl"))
        .into_iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                hex::decode(r["hex"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

fn replay_cases(cases: Vec<serde_json::Value>, what: &str) {
    // a minimal valid transaction, for wrapping apply data
    let txn = seeds()["fx_block_1_txn0"].clone();
    replay::replay(env!("CARGO_MANIFEST_DIR"), cases, what, |kind, b| {
        rust_verdicts(kind, b, &txn)
    });
}

/// Every committed mutant: go's verdict (from the real go decoders) equals
/// every Rust entry point's, and an accepted message decodes to go's value.
#[test]
fn rust_decoders_match_go_on_every_mutated_message() {
    let dir = env!("CARGO_MANIFEST_DIR");
    replay_cases(
        replay::rows(&replay::fixture(dir, "cases.jsonl")),
        "committed",
    );
}

/// A larger one-off differential fuzz: `STRICT_FUZZ_FILE` is the output of
/// `strict_decode_fixtures.py --fuzz N OUT`.
#[test]
fn fuzz_file() {
    let Ok(path) = std::env::var("STRICT_FUZZ_FILE") else {
        eprintln!("STRICT_FUZZ_FILE not set: skipped");
        return;
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    replay_cases(replay::rows(&text), "fuzz");
}

// ── issue #2397: go `string` fields are arbitrary bytes ───────────────────

/// A go-valid message whose `gen` / `proto` / `nextproto` / `upgradeprop` /
/// `type` hold non-UTF-8 bytes (the random seeds) decodes, and re-encodes to
/// the same canonical bytes: nothing is replaced by U+FFFD, so the block hash
/// (and a later header's `nextproto`) stays go's.
#[test]
fn non_utf8_string_fields_round_trip_byte_exact() {
    fn non_utf8_str(b: &[u8]) -> bool {
        // a (fix)str marker followed by bytes that are not valid UTF-8
        (0..b.len().saturating_sub(1)).any(|i| {
            matches!(b[i], 0xa1..=0xbf)
                && std::str::from_utf8(&b[i + 1..(i + 1 + (b[i] & 0x1f) as usize).min(b.len())])
                    .is_err()
        })
    }
    let mut checked = 0;
    for (name, b) in seeds() {
        if !name.contains("_rand") || !non_utf8_str(&b) {
            continue;
        }
        if name.starts_with("header_") {
            let h = BlockHeader::decode_from_bytes(&b).unwrap();
            let re = algo_codec::canonical_encode_block_header(&h);
            assert_eq!(re, b, "{name}: header re-encode differs");
            checked += 1;
        } else if name.starts_with("txn_") {
            let t = Transaction::decode_from_bytes(&b).unwrap();
            let re = algo_codec::canonical_encode_transaction(&t);
            assert_eq!(re, b, "{name}: txn re-encode differs");
            checked += 1;
        } else if name.starts_with("block_") {
            let blk = algo_codec::decode_block(&b).unwrap();
            let re = algo_codec::canonical_encode_block(&blk);
            assert_eq!(re, b, "{name}: block re-encode differs");
            checked += 1;
        }
    }
    assert!(checked >= 3, "no non-UTF-8 random header/block seed");
}
