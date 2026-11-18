// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Replay of a strict-decode fixture set (issue #2396), shared by the
//! non-consensus parity tests of algo-ledger, algo-network and algo-p2p
//! through `#[path]`. It is the Rust twin of `strict_decode_fixtures.py`'s
//! mutator: a case inserts one key/value at a position of the n-th map
//! (pre-order) of a seed, and the fixture's `sha` pins that both produce the
//! same bytes. `verdicts(kind, bytes)` returns every algod-rust entry point
//! that reads `kind` with its accept/reject result; each must equal go's.
//! An entry point that also returns its decoded value, re-encoded the way go
//! encodes it ([`valued`]), must match go's decoded value too: the case's
//! `go_val` is the sha256 prefix of go's re-encode (issue #2421, what a
//! repeated key decodes to).

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

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

/// One map: (start, entries as (key_start, val_end), end).
struct MapInfo {
    start: usize,
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
    let mut j = i + hl;
    if is_map {
        let slot = out.len();
        out.push(None);
        let mut entries = Vec::new();
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
            entries,
            end: j,
        });
    } else {
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
    let m = maps[map as usize].as_ref().expect("map index in range");
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
    let mut out = b[..m.start].to_vec();
    out.extend(map_len_header(m.entries.len() + 1));
    out.extend(body);
    out.extend_from_slice(&b[m.end..]);
    out
}

/// A decoder result as a verdict.
#[allow(dead_code)] // not every replaying test has a verdict-only entry point
pub fn verdict<T, E: std::fmt::Debug>(r: Result<T, E>) -> Result<Option<Vec<u8>>, String> {
    r.map(|_| None).map_err(|e| format!("{e:?}"))
}

/// A decoder result as a verdict plus its decoded value, encoded like go's
/// `protocol.Encode` of the same go value.
#[allow(dead_code)]
pub fn valued<T, E: std::fmt::Debug>(
    r: Result<T, E>,
    encode: impl FnOnce(&T) -> Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    r.map(|v| Some(encode(&v))).map_err(|e| format!("{e:?}"))
}

/// `tests/fixtures/strict_decode/<name>` of the crate under test.
pub fn fixture(manifest_dir: &str, name: &str) -> String {
    let p = format!("{manifest_dir}/tests/fixtures/strict_decode/{name}");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

pub fn rows(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("fixture row is JSON"))
        .collect()
}

pub type Verdicts = Vec<(&'static str, Result<Option<Vec<u8>>, String>)>;

/// Replay `cases` (mutants of the crate's `seeds.jsonl`) through `verdicts`
/// and fail with every case where an algod-rust entry point disagrees with go.
pub fn replay(
    manifest_dir: &str,
    cases: Vec<Value>,
    what: &str,
    verdicts: impl Fn(&str, &[u8]) -> Verdicts,
) {
    let seeds: BTreeMap<String, Vec<u8>> = rows(&fixture(manifest_dir, "seeds.jsonl"))
        .into_iter()
        .map(|r| {
            (
                r["name"].as_str().expect("name").to_string(),
                hex::decode(r["hex"].as_str().expect("hex")).expect("seed hex"),
            )
        })
        .collect();
    let mut mismatches = Vec::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    // `STRICT_MISMATCH_OUT`: every differing mutant as an oracle input row
    // ({"name","kind","hex"}), to read go's decoded value when debugging
    let mut dump = String::new();
    let mut accepted = 0usize;
    for c in &cases {
        let seed = &seeds[c["seed"].as_str().expect("seed")];
        let key = hex::decode(c["key"].as_str().expect("key")).expect("key hex");
        let val = hex::decode(c["val"].as_str().expect("val")).expect("val hex");
        let mutant = mutate(
            seed,
            c["map"].as_i64().expect("map"),
            c["pos"].as_u64().expect("pos") as usize,
            &key,
            &val,
        );
        let sha = hex::encode(&Sha256::digest(&mutant)[..8]);
        assert_eq!(
            sha,
            c["sha"].as_str().expect("sha"),
            "{what} case {}: the Rust mutator diverges from the script's",
            c["id"]
        );
        let kind = c["kind"].as_str().expect("kind");
        let go_ok = c["go_ok"].as_bool().expect("go_ok");
        accepted += go_ok as usize;
        let before = mismatches.len();
        let mut rust_val = String::new();
        let mut rust_err = String::new();
        for (path, rust) in verdicts(kind, &mutant) {
            if let (true, Ok(Some(enc))) = (go_ok, &rust) {
                let got = hex::encode(&Sha256::digest(enc)[..8]);
                let want = c["go_val"].as_str().expect("an accepted case has go_val");
                if got != want {
                    rust_val = hex::encode(enc);
                    mismatches.push(format!(
                        "{what} case {} ({kind}, seed {}, map {}, pos {}, key {}, val {}): {path} decodes another value than go (re-encoded, first 96 bytes: {})",
                        c["id"],
                        c["seed"].as_str().unwrap_or_default(),
                        c["map"],
                        c["pos"],
                        c["key"].as_str().unwrap_or_default(),
                        c["val"].as_str().unwrap_or_default(),
                        hex::encode(&enc[..enc.len().min(96)]),
                    ));
                }
                continue;
            }
            if rust.is_ok() != go_ok {
                mismatches.push(format!(
                    "{what} case {} ({kind}, seed {}, map {}, pos {}, key {}, val {}): go {} but {path} {}{}",
                    c["id"],
                    c["seed"].as_str().unwrap_or_default(),
                    c["map"],
                    c["pos"],
                    c["key"].as_str().unwrap_or_default(),
                    c["val"].as_str().unwrap_or_default(),
                    if go_ok { "accepts" } else { "rejects" },
                    if rust.is_ok() { "accepts" } else { "rejects" },
                    rust.as_ref().err().map(|e| format!(" ({e})")).unwrap_or_default(),
                ));
                if let Err(e) = &rust {
                    rust_err = e.clone();
                }
            }
        }
        if mismatches.len() > before {
            *by_kind.entry(kind.to_string()).or_default() += 1;
            let row = serde_json::json!({
                "name": c["id"].to_string(),
                "kind": kind,
                "hex": hex::encode(&mutant),
                "rust": rust_val,
                "rust_err": rust_err,
            });
            dump.push_str(&format!("{row}\n"));
        }
    }
    if let Ok(out) = std::env::var("STRICT_MISMATCH_OUT") {
        std::fs::write(format!("{out}.{what}"), &dump).expect("write STRICT_MISMATCH_OUT");
    }
    assert!(accepted > 0 && accepted < cases.len(), "degenerate fixture");
    if !mismatches.is_empty() {
        // unmutated seeds first: a seed go accepts and Rust rejects is a reader gap
        mismatches.sort_by_key(|m| !m.contains("map -1"));
        let shown: Vec<_> = mismatches.iter().take(40).cloned().collect();
        panic!(
            "{} of {} {what} cases differ from go (by kind: {by_kind:?}):\n{}",
            by_kind.values().sum::<usize>(),
            cases.len(),
            shown.join("\n")
        );
    }
}

/// The committed cases plus, when `STRICT_FUZZ_FILE` is set, the script's
/// `--fuzz N OUT` output for this set (`OUT.<set>`).
#[allow(dead_code)] // the consensus test replays its own way
pub fn replay_committed_and_fuzz(
    manifest_dir: &str,
    set: &str,
    verdicts: impl Fn(&str, &[u8]) -> Verdicts,
) {
    replay(
        manifest_dir,
        rows(&fixture(manifest_dir, "cases.jsonl")),
        "committed",
        &verdicts,
    );
    if let Ok(path) = std::env::var("STRICT_FUZZ_FILE") {
        let path = format!("{path}.{set}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        replay(manifest_dir, rows(&text), "fuzz", &verdicts);
    }
}
