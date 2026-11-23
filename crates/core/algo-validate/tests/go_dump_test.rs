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

//! go's `transaction <Summary> invalid : <err>` frame, byte for byte (issues #2451, #2551).
//!
//! Every framed `verify.TxnGroup` text go-algorand v5.1.1-stable produced in
//! the two oracles, against `algo_validate::frame_invalid_txn` of the
//! `SignedTxn` decoded from go's own bytes:
//!
//! - `algo-ledger/tests/fixtures/block_checkdup/oracle.json` `wellformed`
//!   (`tools/simulate-rewards-oracle`): one row per `WellFormed` rule, every
//!   transaction type with its fields set, and the signature classes;
//! - `fixtures/pq_failure_texts.jsonl` (`tools/pq-failure-text-oracle`): the
//!   top-level and delegated Falcon-1024 envelopes.
//!
//! Since go v5.1 the frame is `SignedTxn.Summary()` (no pointer address), so
//! nothing is masked.

use algo_types::SignedTransaction;
use algo_validate::frame_invalid_txn;

const PQ_FIXTURE: &str = include_str!("fixtures/pq_failure_texts.jsonl");
const WF_FIXTURE: &str =
    include_str!("../../algo-ledger/tests/fixtures/block_checkdup/oracle.json");

/// The reason after go's frame, for a text that carries it.
fn reason(text: &str) -> Option<&str> {
    const TAIL: &str = " invalid : ";
    let at = text.find(TAIL)?;
    if !text.starts_with("transaction ") || !text[..at].contains(" from ") {
        return None;
    }
    Some(&text[at + TAIL.len()..])
}

/// Whether some member of `group` framed with `reason` is exactly `want`.
fn framed_by_a_member(group: &[SignedTransaction], want: &str) -> Result<(), String> {
    let reason = reason(want).ok_or("not framed")?;
    let mut last = String::new();
    for stx in group {
        let got = frame_invalid_txn(stx, reason);
        if got == want {
            return Ok(());
        }
        last = got;
    }
    let at = want
        .bytes()
        .zip(last.bytes())
        .position(|(a, b)| a != b)
        .unwrap_or(want.len().min(last.len()));
    let lo = at.saturating_sub(80);
    Err(format!(
        "first difference at byte {at}:\n      go:   ...{}\n      rust: ...{}",
        &want[lo..(at + 80).min(want.len())],
        &last[lo..(at + 80).min(last.len())]
    ))
}

#[test]
fn the_frame_of_every_wellformed_and_signature_row_is_gos() {
    let o: serde_json::Value = serde_json::from_str(WF_FIXTURE).expect("oracle JSON");
    let b64 = |s: &str| {
        data_encoding::BASE64
            .decode(s.as_bytes())
            .expect("base64 member")
    };
    let mut compared = 0;
    let mut mismatches = Vec::new();
    for row in o["wellformed"].as_array().expect("wellformed rows") {
        let name = row["name"].as_str().unwrap();
        let want = row["verify_error"].as_str().unwrap();
        if reason(want).is_none() {
            continue;
        }
        let mut group = Vec::new();
        let mut decodes = true;
        for m in row["group"].as_array().unwrap() {
            match algo_codec::decode_signed_txn_stream(&b64(m.as_str().unwrap())) {
                Ok(mut one) => group.append(&mut one),
                Err(_) => decodes = false,
            }
        }
        // go encodes a zero sender as an absent `snd`, which both decoders
        // refuse (issue #2197): such a row never reaches the frame.
        if !decodes {
            continue;
        }
        compared += 1;
        if let Err(e) = framed_by_a_member(&group, want) {
            mismatches.push(format!("{name}: {e}"));
        }
    }
    assert!(
        compared > 150,
        "the oracle has the framed rows ({compared})"
    );
    assert!(
        mismatches.is_empty(),
        "{} frame(s) differ from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
#[ignore = "Phase 26 carve-out: pq_failure_texts.jsonl is PQSig-era; tools/pq-failure-text-oracle is ported to SaltedKeySig and regenerated in #2546"]
fn the_frame_of_every_pq_case_is_gos() {
    let mut compared = 0;
    let mut mismatches = Vec::new();
    for line in PQ_FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let case: serde_json::Value = serde_json::from_str(line).expect("fixture line");
        let (want, stxn) = match case["path"].as_str().unwrap() {
            "pool" => (
                case["want"].as_str().unwrap(),
                case["stxn"].as_str().unwrap(),
            ),
            _ => (
                case["want_failure_message"].as_str().unwrap(),
                case["stxn"].as_str().unwrap(),
            ),
        };
        if reason(want).is_none() {
            continue;
        }
        compared += 1;
        let group = algo_codec::decode_signed_txn_stream(&hex::decode(stxn).unwrap())
            .expect("go's SignedTxn decodes");
        if let Err(e) = framed_by_a_member(&group, want) {
            mismatches.push(format!(
                "{} / {} / {}: {e}",
                case["path"], case["kind"], case["name"]
            ));
        }
    }
    assert!(
        compared >= 30,
        "the PQ oracle has framed cases ({compared})"
    );
    assert!(
        mismatches.is_empty(),
        "{} PQ frame(s) differ from go:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
