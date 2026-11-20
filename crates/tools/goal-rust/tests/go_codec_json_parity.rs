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

//! `goal_rust::go_codec_json` against go-codec itself (issue #2466).
//!
//! `fixtures/go_codec_json_decode.jsonl` holds, for each body of a corpus
//! of valid, truncated and mutated algod answers, what go-algorand
//! v5.0.5-stable's `restClient.submitForm` decode
//! (`protocol.NewJSONDecoder(<http.MaxBytesReader>).Decode(&response)`)
//! made of it: the error text, else the decoded struct as `encoding/json`
//! prints it. `tools/go-codec-json-oracle/main.go` writes it (it reads the
//! `ty` / `body` of each row and writes the row back with go's `err` /
//! `value`; its header has the build steps):
//!
//! ```bash
//! /tmp/go-codec-json-oracle \
//!   < crates/tools/goal-rust/tests/fixtures/go_codec_json_decode.jsonl > /tmp/out.jsonl
//! cmp /tmp/out.jsonl crates/tools/goal-rust/tests/fixtures/go_codec_json_decode.jsonl
//! ```
//!
//! The corpus: well-formed answers of each type, every prefix of them, and
//! random insertions, deletions and replacements of JSON tokens; strings of
//! 55..140 bytes ending in a cut `\u` escape around go-codec's 64-byte
//! scratch buffer; random token soups.

use base64::Engine as _;
use goal_rust::go_codec_json::{
    decode, Ty, ACCOUNT, ACCOUNT_ASSET, ACCOUNT_ASSETS_INFORMATION, APPLICATION, ASSET,
    CATCHPOINT_RESPONSE, NODE_STATUS, PARTICIPATION_KEYS, PENDING_TRANSACTION, POST_PARTICIPATION,
    POST_TRANSACTIONS, SUPPLY, TRANSACTION_PARAMETERS, VERSION,
};

const FIXTURE: &str = include_str!("fixtures/go_codec_json_decode.jsonl");

fn ty(name: &str) -> &'static Ty {
    match name {
        "account" => &ACCOUNT,
        "version" => &VERSION,
        "status" => &NODE_STATUS,
        "supply" => &SUPPLY,
        "asset" => &ASSET,
        "application" => &APPLICATION,
        "account-assets" => &ACCOUNT_ASSETS_INFORMATION,
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

#[test]
fn go_codec_json_decode_matches_go() {
    let mut mismatches = Vec::new();
    let mut rows = 0;
    for line in FIXTURE.lines() {
        rows += 1;
        let row: serde_json::Value = serde_json::from_str(line).expect("fixture row");
        let body = base64::engine::general_purpose::STANDARD
            .decode(row["body"].as_str().expect("body"))
            .expect("base64 body");
        let got = decode(&body, ty(row["ty"].as_str().expect("ty")));
        let ok = match (&got, row["err"].as_str()) {
            (Err(e), Some(want)) => e.to_string() == want,
            (Ok(v), None) => *v == row["value"],
            _ => false,
        };
        if !ok {
            mismatches.push(format!(
                "{} {:?}:\n  go:   {} {}\n  rust: {:?}",
                row["ty"],
                String::from_utf8_lossy(&body),
                row["err"],
                row["value"],
                got
            ));
        }
    }
    assert!(rows > 1000, "the corpus is unexpectedly small");
    assert!(
        mismatches.is_empty(),
        "{} of {rows} bodies decode differently from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
