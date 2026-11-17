// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict unknown-field parity with go-algorand (issue #2394).
//!
//! go decodes every msgpack message with generated msgp decoders, where a key
//! the target struct lacks is `msgp.ErrNoField` and the message is dropped
//! (`protocol.CodecHandle.ErrorIfNoField = true` on the reflection path).
//! `tests/fixtures/strict_decode/` holds valid messages (`seeds.jsonl`, real
//! blocks/votes plus go-encoded fully populated random objects) and mutants of
//! them with go's accept/reject verdict (`cases.jsonl`), produced by
//! `scripts/strict-decode/strict_decode_fixtures.py` running go's real decoders
//! (tools/strict-decode-oracle). Every entry point of algod-rust that reads
//! one of those message kinds must give the same verdict on every case.
//!
//! The mutator below mirrors the script's (insert a key/value at a position of
//! the n-th map, pre-order); the fixture's `sha` pins that both produce the
//! same bytes.

use std::collections::BTreeMap;

use algo_agreement::codec::{decode_bundle, decode_compound_message, decode_vote};
use algo_types::{BlockHeader, SignedTransaction, Transaction};
use serde_json::Value;
use sha2::{Digest, Sha256};

// ── raw msgpack walking ───────────────────────────────────────────────────

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

/// One map: (start, header_len, entries as (key_start, val_end), end).
struct MapInfo {
    start: usize,
    header_len: usize,
    entries: Vec<(usize, usize)>,
    end: usize,
}

fn walk_maps(b: &[u8], i: usize, out: &mut Vec<Option<MapInfo>>) {
    let c = b[i];
    let (n, hl, is_map) = match c {
        0x80..=0x8f => ((c & 0x0f) as usize, 1, true),
        0xde => (be(b, i + 1, 2), 3, true),
        0xdf => (be(b, i + 1, 4), 5, true),
        0x90..=0x9f => ((c & 0x0f) as usize, 1, false),
        0xdc => (be(b, i + 1, 2), 3, false),
        0xdd => (be(b, i + 1, 4), 5, false),
        _ => return,
    };
    if is_map {
        let slot = out.len();
        out.push(None);
        let mut entries = Vec::new();
        let mut j = i + hl;
        for _ in 0..n {
            let ks = j;
            let vs = skip(b, ks);
            walk_maps(b, ks, out);
            walk_maps(b, vs, out);
            let ve = skip(b, vs);
            entries.push((ks, ve));
            j = ve;
        }
        out[slot] = Some(MapInfo {
            start: i,
            header_len: hl,
            entries,
            end: j,
        });
    } else {
        let mut j = i + hl;
        for _ in 0..n {
            walk_maps(b, j, out);
            j = skip(b, j);
        }
    }
}

fn map_len_header(n: usize) -> Vec<u8> {
    if n < 16 {
        vec![0x80 | n as u8]
    } else if n < 65536 {
        let mut v = vec![0xde];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else {
        let mut v = vec![0xdf];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    }
}

fn mutate(b: &[u8], map: i64, pos: usize, key: &[u8], val: &[u8]) -> Vec<u8> {
    if map < 0 {
        return b.to_vec();
    }
    let mut maps = Vec::new();
    walk_maps(b, 0, &mut maps);
    let m = maps[map as usize].as_ref().unwrap();
    let pos = pos.min(m.entries.len());
    let mut body = Vec::new();
    for (k, &(ks, ve)) in m.entries.iter().enumerate() {
        if k == pos {
            body.extend_from_slice(key);
            body.extend_from_slice(val);
        }
        body.extend_from_slice(&b[ks..ve]);
    }
    if pos == m.entries.len() {
        body.extend_from_slice(key);
        body.extend_from_slice(val);
    }
    let _ = m.header_len;
    let mut out = b[..m.start].to_vec();
    out.extend(map_len_header(m.entries.len() + 1));
    out.extend(body);
    out.extend_from_slice(&b[m.end..]);
    out
}

// ── the entry points under test ───────────────────────────────────────────

const APPLY_DATA_KEYS: [&[u8]; 8] = [b"ca", b"dt", b"rs", b"rr", b"rc", b"aca", b"apid", b"caid"];

/// `applydata` / `evaldelta` have no standalone reader in algod-rust (they
/// only occur inside a block's `SignedTxnInBlock`): embed the value in a
/// minimal valid signed transaction and decode that. go's `ApplyData` has
/// exactly the eight keys above, so a key outside them is rejected here.
fn wrap_in_stxn(kind: &str, b: &[u8], txn: &[u8]) -> Option<Vec<u8>> {
    let mut ad_entries: Vec<&[u8]> = Vec::new();
    let mut maps = Vec::new();
    walk_maps(b, 0, &mut maps);
    let mut stxn = Vec::new();
    if kind == "evaldelta" {
        // the value of `dt`
        let n = 1;
        stxn.extend(map_len_header(n + 1));
        stxn.extend_from_slice(b"\xa3txn");
        stxn.extend_from_slice(txn);
        stxn.extend_from_slice(b"\xa2dt");
        stxn.extend_from_slice(b);
        return Some(stxn);
    }
    let m = maps[0].as_ref()?;
    for &(ks, ve) in &m.entries {
        let ke = skip(b, ks);
        let key = &b[ks..ke];
        // fixstr key
        if key.is_empty() || key[0] & 0xe0 != 0xa0 || !APPLY_DATA_KEYS.contains(&&key[1..]) {
            return None;
        }
        ad_entries.push(&b[ks..ve]);
    }
    stxn.extend(map_len_header(ad_entries.len() + 1));
    stxn.extend_from_slice(b"\xa3txn");
    stxn.extend_from_slice(txn);
    for e in ad_entries {
        stxn.extend_from_slice(e);
    }
    Some(stxn)
}

/// (entry point name, accepted?) for every Rust decoder that reads `kind`.
fn verdict<T, E: std::fmt::Display + std::fmt::Debug>(r: Result<T, E>) -> Result<(), String> {
    r.map(|_| ()).map_err(|e| format!("{e:?} / {e}"))
}

fn rust_verdicts(kind: &str, b: &[u8], txn: &[u8]) -> Vec<(&'static str, Result<(), String>)> {
    match kind {
        "payload" => vec![(
            "decode_compound_message",
            verdict(decode_compound_message(b)),
        )],
        "vote" => vec![("decode_vote", verdict(decode_vote(b)))],
        "bundle" | "cert" => vec![("decode_bundle", verdict(decode_bundle(b)))],
        "blockcert" => vec![
            (
                "decode_block_response",
                verdict(algo_codec::decode_block_response(b)),
            ),
            (
                "decode_block_response_fast",
                verdict(algo_codec::decode_block_response_fast(b)),
            ),
        ],
        "block" => vec![
            ("decode_block", verdict(algo_codec::decode_block(b))),
            (
                "decode_block_fast",
                verdict(algo_codec::decode_block_fast(b)),
            ),
        ],
        "header" => vec![(
            "BlockHeader::decode_from_bytes",
            verdict(BlockHeader::decode_from_bytes(b)),
        )],
        "stxn" => {
            let _g = algo_types::strict_unknown_fields(b);
            vec![(
                "SignedTransaction (strict guard)",
                verdict(SignedTransaction::decode_from_bytes(b)),
            )]
        }
        "stxninblock" => vec![(
            "SignedTransaction (block)",
            verdict(SignedTransaction::decode_from_bytes(b)),
        )],
        "txn" => vec![(
            "Transaction::decode_from_bytes",
            verdict(Transaction::decode_from_bytes(b)),
        )],
        "applydata" | "evaldelta" => match wrap_in_stxn(kind, b, txn) {
            Some(w) => vec![(
                "SignedTransaction (block, wrapped)",
                verdict(SignedTransaction::decode_from_bytes(&w)),
            )],
            None => vec![(
                "(top-level key outside ApplyData)",
                Err("top-level key outside ApplyData".into()),
            )],
        },
        other => panic!("unknown kind {other}"),
    }
}

fn fixture(name: &str) -> String {
    let p = format!(
        "{}/tests/fixtures/strict_decode/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn rows(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn seeds() -> BTreeMap<String, Vec<u8>> {
    rows(&fixture("seeds.jsonl"))
        .into_iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                hex::decode(r["hex"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

/// A minimal valid transaction, for wrapping apply data.
fn wrapper_txn(seeds: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    seeds["fx_block_1_txn0"].clone()
}

fn replay(cases: Vec<Value>, what: &str) {
    let seeds = seeds();
    let txn = wrapper_txn(&seeds);
    let mut mismatches = Vec::new();
    let mut accepted = 0usize;
    let mut by_kind: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for c in &cases {
        let seed = &seeds[c["seed"].as_str().unwrap()];
        let key = hex::decode(c["key"].as_str().unwrap()).unwrap();
        let val = hex::decode(c["val"].as_str().unwrap()).unwrap();
        let mutant = mutate(
            seed,
            c["map"].as_i64().unwrap(),
            c["pos"].as_u64().unwrap() as usize,
            &key,
            &val,
        );
        let sha = hex::encode(&Sha256::digest(&mutant)[..8]);
        assert_eq!(
            sha,
            c["sha"].as_str().unwrap(),
            "{what} case {}: the Rust mutator diverges from the script's",
            c["id"]
        );
        let kind = c["kind"].as_str().unwrap();
        let go_ok = c["go_ok"].as_bool().unwrap();
        accepted += go_ok as usize;
        by_kind.entry(kind.to_string()).or_default().0 += 1;
        for (path, rust) in rust_verdicts(kind, &mutant, &txn) {
            let rust_ok = rust.is_ok();
            if rust_ok != go_ok {
                by_kind.entry(kind.to_string()).or_default().1 += 1;
                mismatches.push(format!(
                    "{what} case {} ({kind}, seed {}, map {}, pos {}, key {}, val {}): go {} but {path} {}{}",
                    c["id"],
                    c["seed"].as_str().unwrap(),
                    c["map"],
                    c["pos"],
                    c["key"].as_str().unwrap(),
                    c["val"].as_str().unwrap(),
                    if go_ok { "accepts" } else { "rejects" },
                    if rust_ok { "accepts" } else { "rejects" },
                    rust.as_ref().err().map(|e| format!(" ({e})")).unwrap_or_default(),
                ));
            }
        }
    }
    assert!(accepted > 0 && accepted < cases.len(), "degenerate fixture");
    if !mismatches.is_empty() {
        // unmutated seeds first: a seed go accepts and Rust rejects is a reader gap
        mismatches.sort_by_key(|m| !m.contains("map -1"));
        let shown: Vec<_> = mismatches.iter().take(40).cloned().collect();
        panic!(
            "{} of {} {what} cases differ from go:\n{}",
            mismatches.len(),
            cases.len(),
            shown.join("\n")
        );
    }
}

/// Every committed mutant: go's verdict (from the real go decoders) equals
/// every Rust entry point's.
#[test]
fn rust_decoders_match_go_on_every_mutated_message() {
    replay(rows(&fixture("cases.jsonl")), "committed");
}

/// A larger one-off differential fuzz: `STRICT_FUZZ_FILE` is the output of
/// `strict_decode_fixtures.py --fuzz N OUT`.
#[test]
fn fuzz_file() {
    let Ok(path) = std::env::var("STRICT_FUZZ_FILE") else {
        eprintln!("STRICT_FUZZ_FILE not set: skipped");
        return;
    };
    let text = std::fs::read_to_string(&path).unwrap();
    replay(rows(&text), "fuzz");
}
