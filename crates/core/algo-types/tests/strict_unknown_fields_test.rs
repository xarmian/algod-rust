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

//! Strict unknown-field mode of the hand-written msgpack readers (issue #1962).
//!
//! go-algorand's `POST /v2/transactions` decodes with `protocol.NewDecoder`
//! (`ErrorIfNoField = true`), so a body with a key its structs do not have is
//! a 400 whose text names the stream offset just after that key:
//!
//!   msgpack decode error [pos N]: no matching struct field found when decoding stream map with key K
//!
//! The expected positions below were captured from a real go-algorand
//! v5.0.3-stable node (`algorand/algod:5.0.3-stable`, private network,
//! `curl -X POST --data-binary @body /v2/transactions`) for exactly these
//! bodies. Without the strict guard the readers keep skipping unknown keys,
//! which blocks and catchup rely on.

use algo_error::AlgoError;
use algo_types::{
    strict_unknown_fields, strict_unknown_fields_scan, SignedTransaction, UnknownFieldError,
};

fn s(x: &str) -> Vec<u8> {
    assert!(x.len() < 32);
    let mut v = vec![0xa0 + x.len() as u8];
    v.extend_from_slice(x.as_bytes());
    v
}
fn bin(b: &[u8]) -> Vec<u8> {
    let mut v = vec![0xc4, b.len() as u8];
    v.extend_from_slice(b);
    v
}
fn uint(n: u16) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else {
        vec![0xcd, (n >> 8) as u8, n as u8]
    }
}
fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut v = vec![0x80 + pairs.len() as u8];
    for (k, val) in pairs {
        v.extend(s(k));
        v.extend(val);
    }
    v
}
fn txn(extra: Option<(&'static str, Vec<u8>)>) -> Vec<u8> {
    let mut p = vec![
        ("amt", uint(1000)),
        ("fee", uint(1000)),
        ("fv", uint(100)),
        ("gh", bin(&[3u8; 32])),
        ("lv", uint(1100)),
        ("rcv", bin(&[2u8; 32])),
        ("snd", bin(&[1u8; 32])),
        ("type", s("pay")),
    ];
    if let Some(e) = extra {
        p.push(e);
    }
    map(p)
}
fn sig() -> (&'static str, Vec<u8>) {
    ("sig", bin(&[7u8; 64]))
}

fn ok_stxn() -> Vec<u8> {
    map(vec![("txn", txn(None)), sig()])
}

/// Decode the whole body (a txn group) in strict mode; the first error.
fn decode_strict(body: &[u8]) -> Result<usize, AlgoError> {
    let _guard = strict_unknown_fields(body);
    let mut cur = body;
    let mut n = 0;
    while !cur.is_empty() {
        SignedTransaction::decode_from_reader(&mut cur)?;
        n += 1;
    }
    Ok(n)
}

fn unknown(e: AlgoError) -> UnknownFieldError {
    match e {
        AlgoError::Codec { source, .. } => *source
            .downcast::<UnknownFieldError>()
            .unwrap_or_else(|e| panic!("not an UnknownFieldError: {e}")),
        other => panic!("not a codec error: {other}"),
    }
}

fn go_text(pos: usize, key: &str) -> String {
    format!(
        "msgpack decode error [pos {pos}]: no matching struct field found when decoding stream map with key {key}"
    )
}

fn check(body: &[u8], pos: usize, key: &str) {
    let u = unknown(decode_strict(body).expect_err("must be rejected"));
    assert_eq!(u.to_string(), go_text(pos, key));
    assert_eq!((u.pos, u.key.as_str()), (pos, key));
}

#[test]
fn a_clean_body_decodes_in_strict_mode() {
    assert_eq!(decode_strict(&ok_stxn()).unwrap(), 1);
    let mut group = ok_stxn();
    group.extend(ok_stxn());
    assert_eq!(decode_strict(&group).unwrap(), 2);
}

#[test]
fn unknown_key_at_the_signed_txn_level() {
    check(&map(vec![("txn", txn(None)), sig(), ("zzz", uint(1))]), 226, "zzz");
}

#[test]
fn unknown_key_inside_the_transaction() {
    check(&map(vec![("txn", txn(Some(("zzz", uint(1))))), sig()]), 156, "zzz");
}

#[test]
fn unknown_key_inside_a_logicsig() {
    let lsig = map(vec![("l", bin(&[6, 0x81, 1])), ("zzz", uint(1))]);
    check(&map(vec![("txn", txn(None)), ("lsig", lsig)]), 169, "zzz");
}

#[test]
fn unknown_key_inside_a_multisig_subsig() {
    let subsig = {
        let mut v = vec![0x91];
        v.extend(map(vec![("pk", bin(&[5u8; 32])), ("zzz", uint(1))]));
        v
    };
    let msig = map(vec![("v", uint(1)), ("thr", uint(1)), ("subsig", subsig)]);
    check(&map(vec![("txn", txn(None)), ("msig", msig)]), 216, "zzz");
}

#[test]
fn unknown_key_inside_a_pqsig() {
    let pq = map(vec![("sch", bin(b"f1")), ("zzz", uint(1))]);
    check(&map(vec![("txn", txn(None)), ("pqsig", pq)]), 171, "zzz");
}

/// The position is the offset into the WHOLE body, as go's stream decoder counts.
#[test]
fn the_position_counts_from_the_start_of_the_group() {
    let bad_top = map(vec![("txn", txn(None)), sig(), ("zzz", uint(1))]);
    let bad_txn = map(vec![("txn", txn(Some(("zzz", uint(1))))), sig()]);
    let mut g = ok_stxn();
    g.extend(&bad_top);
    check(&g, 448, "zzz");
    let mut g = bad_top.clone();
    g.extend(ok_stxn());
    check(&g, 226, "zzz");
    let mut g = ok_stxn();
    g.extend(&bad_txn);
    check(&g, 378, "zzz");
}

/// Keys that only exist in a block's SignedTxnInBlock are unknown to go's SignedTxn.
#[test]
fn in_block_only_keys_are_unknown_in_strict_mode() {
    let t = || ("txn", txn(None));
    check(&map(vec![("hgi", vec![0xc3]), sig(), t()]), 5, "hgi");
    check(&map(vec![("hgh", vec![0xc3]), sig(), t()]), 5, "hgh");
    check(&map(vec![("ca", uint(5)), sig(), t()]), 4, "ca");
    check(&map(vec![("apid", uint(5)), sig(), t()]), 6, "apid");
    // the first unknown key in stream order wins
    check(&map(vec![("hgh", vec![0xc3]), ("hgi", vec![0xc3]), sig(), t()]), 5, "hgh");
}

/// Every key the SignedTransaction reader accepts only because blocks carry it.
#[test]
fn every_block_only_key_is_unknown_in_strict_mode() {
    for key in ["ca", "dt", "rs", "rr", "rc", "aca", "hgi", "hgh", "apid", "caid"] {
        let body = map(vec![(key, uint(1)), sig(), ("txn", txn(None))]);
        let u = unknown(decode_strict(&body).expect_err(key));
        assert_eq!(u.key, key);
        assert_eq!(u.pos, 2 + key.len(), "{key}: just after the first key");
        assert_eq!(u.to_string(), go_text(2 + key.len(), key));
    }
}

/// The nested readers of a transaction (asset params, state schemas, boxes,
/// heartbeat) are strict too, not just the SignedTxn envelope.
#[test]
fn unknown_key_inside_nested_transaction_structs_is_rejected() {
    let nested = |outer: &'static str, inner: Vec<u8>| {
        map(vec![("txn", txn(Some((outer, inner)))), sig()])
    };
    let bad_map = || map(vec![("zzz", uint(1))]);
    let cases = vec![
        ("apar", bad_map()),
        ("apgs", bad_map()),
        ("apls", bad_map()),
        ("hb", bad_map()),
        ("apbx", {
            let mut v = vec![0x91];
            v.extend(bad_map());
            v
        }),
    ];
    for (outer, inner) in cases {
        let u = unknown(decode_strict(&nested(outer, inner)).expect_err(outer));
        assert_eq!(u.key, "zzz", "{outer}");
        assert!(u.pos > 0, "{outer}");
    }
}

/// go's JSON decoder enforces no required fields, so for a JSON body it
/// reaches an unknown key that follows an object missing `snd` / `type`
/// (issue #1971). The msgpack-style readers stop at the missing field first;
/// scan mode skips those checks so the unknown key can be located.
#[test]
fn scan_mode_reaches_an_unknown_key_after_an_object_missing_required_fields() {
    // {"txn": {"type": "pay"}, "zzz": 1}: no sender
    let body = map(vec![
        ("txn", map(vec![("type", s("pay"))])),
        ("zzz", uint(1)),
    ]);

    // plain strict mode: the missing required field is the first error
    let err = decode_strict(&body).expect_err("missing snd");
    assert!(matches!(&err, AlgoError::Codec { source, .. } if !source.is::<UnknownFieldError>()), "{err}");

    // scan mode runs on to the unknown key, at go's key position
    let _guard = strict_unknown_fields_scan(&body);
    let mut cur = &body[..];
    let u = unknown(SignedTransaction::decode_from_reader(&mut cur).expect_err("unknown key"));
    assert_eq!(u.key, "zzz");
    drop(_guard);

    // and the mode is scoped: required checks are back afterwards
    let _strict = strict_unknown_fields(&body);
    let mut cur = &body[..];
    assert!(SignedTransaction::decode_from_reader(&mut cur).is_err());
}

/// A plain strict guard created inside a scan guard enforces required fields
/// again, and dropping it restores scan mode for the outer guard.
#[test]
fn a_nested_strict_guard_does_not_inherit_scan_mode() {
    let body = map(vec![
        ("txn", map(vec![("type", s("pay"))])),
        ("zzz", uint(1)),
    ]);
    let _scan = strict_unknown_fields_scan(&body);
    {
        let _strict = strict_unknown_fields(&body);
        let mut cur = &body[..];
        let err = SignedTransaction::decode_from_reader(&mut cur).expect_err("missing snd");
        assert!(
            matches!(&err, AlgoError::Codec { source, .. } if !source.is::<UnknownFieldError>()),
            "{err}"
        );
    }
    // back in the outer scan guard: the unknown key is reached again
    let mut cur = &body[..];
    let u = unknown(SignedTransaction::decode_from_reader(&mut cur).expect_err("unknown key"));
    assert_eq!(u.key, "zzz");
}

/// Outside strict mode the readers still skip unknown keys (blocks, catchup).
#[test]
fn without_the_guard_unknown_keys_are_still_skipped() {
    for body in [
        map(vec![("txn", txn(None)), sig(), ("zzz", uint(1))]),
        map(vec![("txn", txn(Some(("zzz", uint(1))))), sig()]),
        map(vec![("hgi", vec![0xc3]), sig(), ("txn", txn(None))]),
    ] {
        let mut cur = &body[..];
        SignedTransaction::decode_from_reader(&mut cur).expect("lenient decode");
    }
}

#[test]
fn the_guard_is_scoped_and_does_not_leak_to_a_later_decode() {
    let bad = map(vec![("txn", txn(None)), sig(), ("zzz", uint(1))]);
    assert!(decode_strict(&bad).is_err());
    let mut cur = &bad[..];
    SignedTransaction::decode_from_reader(&mut cur).expect("lenient again after the guard dropped");
}
