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

//! The answers go-codec never finishes decoding (issue #2537).
//!
//! An array cut after a comma (`{"versions":["v1",`,
//! `{"params":{"approval-program":[1,`) makes go's decoder loop forever: each
//! round's `ReadArrayElem` reads back the `,` the last element handed back
//! (`unreadn1`), the loop starts again in the state it was in, and a slice
//! grows by one element per round until the process runs out of memory
//! (go-codec v1.1.10 `Decoder.kSlice`, `jsonDecDriver.ReadArrayElem`).
//! goal-rust reproduces that: `go_codec_json::decode` has no end for such a
//! body. These tests use the guarded entry point,
//! `decode_guarded(body, ty, max_loop_iterations)`, which stops a container
//! loop after that many rounds with `Error::Endless`, so they can assert the
//! behaviour without hanging.
//!
//! `fixtures/go_codec_json_endless.jsonl` holds the bodies go v5.0.5-stable's
//! decoder (`tools/go-codec-json-oracle`) does not finish: every prefix of the
//! valid bodies of `go_codec_json_decode.jsonl` cut after a `[` or `,`, plus
//! hand-made truncated arrays, each run as `timeout -s KILL 1.5` (a decode
//! that finishes takes milliseconds) with the oracle on stdin; 41 of ~2200
//! candidates did not return. What the tests verify: each body loops in
//! goal-rust, with its slice growing; every body go finishes (the corpus of
//! `go_codec_json_decode.jsonl`) finishes under the guard with the same
//! value. What they cannot verify: the out-of-memory death itself.

use base64::Engine as _;
use goal_rust::go_codec_json::{
    decode, decode_guarded, Error, Ty, ACCOUNT, ACCOUNT_APPLICATIONS_INFORMATION, ACCOUNT_ASSET,
    ACCOUNT_ASSETS_INFORMATION, APPLICATION, ASSET, CATCHPOINT_RESPONSE, NODE_STATUS,
    PARTICIPATION_KEYS, PENDING_TRANSACTION, POST_PARTICIPATION, POST_TRANSACTIONS, SUPPLY,
    TRANSACTION_PARAMETERS, VERSION,
};

const ENDLESS: &str = include_str!("fixtures/go_codec_json_endless.jsonl");
const CORPUS: &str = include_str!("fixtures/go_codec_json_decode.jsonl");

/// Rounds of one container loop a legitimate answer never reaches (the
/// largest corpus array has a few dozen elements).
const GUARD: u64 = 20_000;

fn ty(name: &str) -> &'static Ty {
    match name {
        "account" => &ACCOUNT,
        "version" => &VERSION,
        "status" => &NODE_STATUS,
        "supply" => &SUPPLY,
        "asset" => &ASSET,
        "application" => &APPLICATION,
        "account-assets" => &ACCOUNT_ASSETS_INFORMATION,
        "account-applications" => &ACCOUNT_APPLICATIONS_INFORMATION,
        "account-asset" => &ACCOUNT_ASSET,
        "participation-keys" => &PARTICIPATION_KEYS,
        "post-participation" => &POST_PARTICIPATION,
        "catchpoint" => &CATCHPOINT_RESPONSE,
        "params" => &TRANSACTION_PARAMETERS,
        "post-transactions" => &POST_TRANSACTIONS,
        "pending" => &PENDING_TRANSACTION,
        other => panic!("unknown type {other}"),
    }
}

fn rows(text: &str) -> Vec<(String, Vec<u8>, serde_json::Value)> {
    text.lines()
        .map(|l| {
            let row: serde_json::Value = serde_json::from_str(l).expect("fixture row");
            let body = base64::engine::general_purpose::STANDARD
                .decode(row["body"].as_str().expect("body"))
                .expect("base64 body");
            (row["ty"].as_str().expect("ty").to_string(), body, row)
        })
        .collect()
}

#[test]
fn every_body_go_never_finishes_loops_and_grows_its_slice() {
    let all = rows(ENDLESS);
    assert!(all.len() >= 40, "the endless corpus is unexpectedly small");
    let mut failures = Vec::new();
    for (name, body, _) in &all {
        match decode_guarded(body, ty(name), GUARD) {
            Err(Error::Endless {
                iterations,
                elements,
            }) if iterations > GUARD && elements as u64 >= GUARD / 2 => {}
            other => failures.push(format!(
                "{name} {:?}: {other:?}",
                String::from_utf8_lossy(body)
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} bodies do not loop like go's:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_body_go_finishes_finishes_under_the_guard_with_its_value() {
    let all = rows(CORPUS);
    assert!(all.len() > 1000, "the corpus is unexpectedly small");
    for (name, body, _) in &all {
        let guarded = decode_guarded(body, ty(name), GUARD);
        let plain = decode(body, ty(name));
        match (guarded, plain) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{name} {:?}", String::from_utf8_lossy(body)),
            (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
            (a, b) => panic!(
                "{name} {:?}: guarded {a:?} vs plain {b:?}",
                String::from_utf8_lossy(body)
            ),
        }
    }
}
