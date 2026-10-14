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

//! Byte-level parity of deterministic Falcon-1024 (`det1024`) against the
//! go-algorand-generated vector corpus (issue #1928, epic #1926).
//!
//! Corpus: `tests/fixtures/falcon/vectors.jsonl`. It is produced by
//! `tools/falcon-vector-capture` (Go, linking go-algorand's `crypto`
//! package; regenerated and diffed in CI by `falcon-vectors.yml`) and
//! reproduced byte-for-byte by `examples/gen_vectors.rs`. Record kinds:
//!
//! - `key`: `{kind,name,seed,pubkey,privkey}` — one per seed.
//! - `sig`: `{kind,name,seed,msg,sig_compressed,sig_ct,salt_version}`.
//! - `negative`: `{kind,name,pubkey,msg,sig,expect:"reject"}` — malformed or
//!   mismatched inputs that every implementation must reject.
//! - `verify_only`: `{kind,name,pubkey,msg,sig,expect:"accept"}` — the
//!   signature go-algorand hard-codes in
//!   `data/transactions/logic/crypto_test.go` (`BenchmarkVerify`,
//!   `falcon_verify` case).
//!
//! This is the acceptance test for `DIV-001` (`docs/DIVERGENCES.md`): the
//! pure-Rust port must pass it unchanged.

// Runs against the default backend; until the Rust port is complete (#1937)
// only a build with the C backend has one. From then on it runs for every
// backend in `FalconBackend::all()`.
#![cfg(feature = "c-backend")]

use std::collections::HashMap;
use std::path::PathBuf;

use algo_falcon::{
    falcon_convert_compressed_to_ct, falcon_keygen, falcon_salt_version, falcon_sign, falcon_verify,
};
use serde_json::Value;

const SEED_COUNT: usize = 12;
const MSG_COUNT: usize = 6;
const NEGATIVE_PAIRS: usize = 2;
const NEGATIVE_CASES: usize = 14;

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/falcon/vectors.jsonl");
    p
}

fn load() -> Vec<Value> {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}\nregenerate with `cargo run -p algo-falcon --example gen_vectors` \
             (vendored C) or `cd tools/falcon-vector-capture && go run .` (go-algorand)",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSONL line: {e}: {l}")))
        .collect()
}

fn s<'a>(rec: &'a Value, key: &str) -> &'a str {
    rec[key]
        .as_str()
        .unwrap_or_else(|| panic!("record {} lacks string field {key}", rec["name"]))
}

fn h(rec: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(rec, key)).unwrap_or_else(|e| panic!("record {} field {key}: {e}", rec["name"]))
}

fn of_kind<'a>(recs: &'a [Value], kind: &str) -> Vec<&'a Value> {
    recs.iter().filter(|r| r["kind"] == kind).collect()
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() {
        return Some(a.len().min(b.len()));
    }
    a.iter().zip(b).position(|(x, y)| x != y)
}

#[track_caller]
fn assert_bytes(name: &str, what: &str, want: &[u8], got: &[u8]) {
    if let Some(i) = first_diff(want, got) {
        panic!(
            "falcon parity divergence in {what} for {name:?}: first mismatch at byte {i} \
             (want {} bytes, got {} bytes)\n  want = {}\n  got  = {}",
            want.len(),
            got.len(),
            hex::encode(want),
            hex::encode(got)
        );
    }
}

/// seed hex -> (pubkey, privkey) from the `key` records.
fn keys(recs: &[Value]) -> HashMap<String, (Vec<u8>, Vec<u8>)> {
    of_kind(recs, "key")
        .into_iter()
        .map(|r| (s(r, "seed").to_string(), (h(r, "pubkey"), h(r, "privkey"))))
        .collect()
}

#[test]
fn corpus_has_the_expected_shape() {
    let recs = load();
    assert_eq!(of_kind(&recs, "key").len(), SEED_COUNT);
    assert_eq!(of_kind(&recs, "sig").len(), SEED_COUNT * MSG_COUNT);
    assert_eq!(
        of_kind(&recs, "negative").len(),
        NEGATIVE_PAIRS * NEGATIVE_CASES
    );
    assert_eq!(of_kind(&recs, "verify_only").len(), 1);
    assert_eq!(
        recs.len(),
        SEED_COUNT + SEED_COUNT * MSG_COUNT + NEGATIVE_PAIRS * NEGATIVE_CASES + 1,
        "unknown record kinds present"
    );
    let mut names: Vec<&str> = recs.iter().map(|r| s(r, "name")).collect();
    let n = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), n, "record names must be unique");
    assert_eq!(
        s(of_kind(&recs, "verify_only")[0], "name"),
        "go/crypto_test_falcon_verify"
    );
}

#[test]
fn keygen_matches_corpus() {
    for rec in of_kind(&load(), "key") {
        let name = s(rec, "name");
        let (pk, sk) = falcon_keygen(&h(rec, "seed")).expect("keygen");
        assert_bytes(name, "pubkey", &h(rec, "pubkey"), &pk);
        assert_bytes(name, "privkey", &h(rec, "privkey"), &sk);
    }
}

#[test]
fn sign_matches_corpus() {
    let recs = load();
    let keys = keys(&recs);
    for rec in of_kind(&recs, "sig") {
        let name = s(rec, "name");
        let (_, sk) = &keys[s(rec, "seed")];
        let msg = h(rec, "msg");
        let sig = falcon_sign(sk, &msg).expect("sign");
        assert_bytes(name, "sig_compressed", &h(rec, "sig_compressed"), &sig);
        assert_eq!(
            falcon_salt_version(&sig).expect("salt version") as u64,
            rec["salt_version"].as_u64().expect("salt_version"),
            "{name}: salt version"
        );
        let ct = falcon_convert_compressed_to_ct(&sig).expect("convert to CT");
        assert_bytes(name, "sig_ct", &h(rec, "sig_ct"), &ct);
    }
}

#[test]
fn verify_accepts_corpus_signatures() {
    let recs = load();
    let keys = keys(&recs);
    for rec in of_kind(&recs, "sig") {
        let (pk, _) = &keys[s(rec, "seed")];
        let ok = falcon_verify(pk, &h(rec, "sig_compressed"), &h(rec, "msg"));
        assert!(ok.expect("verify"), "{}: must verify", s(rec, "name"));
    }
}

#[test]
fn verify_rejects_negative_corpus() {
    for rec in of_kind(&load(), "negative") {
        assert_eq!(s(rec, "expect"), "reject");
        let r = falcon_verify(&h(rec, "pubkey"), &h(rec, "sig"), &h(rec, "msg"));
        assert!(
            !matches!(r, Ok(true)),
            "{}: must be rejected, got {r:?}",
            s(rec, "name")
        );
    }
}

#[test]
fn verify_accepts_go_algorand_hard_coded_vector() {
    for rec in of_kind(&load(), "verify_only") {
        assert_eq!(s(rec, "expect"), "accept");
        let r = falcon_verify(&h(rec, "pubkey"), &h(rec, "sig"), &h(rec, "msg"));
        assert!(r.expect("verify"), "{}: must verify", s(rec, "name"));
    }
}
