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

//! Strict decoding of a msgpack `POST /v2/transactions/simulate` request
//! (issue #1967).
//!
//! go's `SimulateTransaction` (`daemon/algod/api/server/v2/handlers.go`
//! ~1562) decodes the body into `PreEncodedSimulateRequest` with
//! `protocol.CodecHandle` (`ErrorIfNoField = true`) and, when that fails,
//! retries with `protocol.JSONStrictHandle` on the same bytes. A msgpack body
//! the first decode rejects -- an unknown key at the request, the
//! transaction-group, the `SignedTxn` or any nested level, including the
//! block-only `hgi`/`hgh` -- therefore always ends in the JSON decoder
//! choking on the msgpack map marker, so the response is one fixed text
//! (captured from a go-algorand v5.0.3-stable node for these bodies):
//!
//! ```text
//! failed to decode object: json decode error [pos 1]: only encoded map or array can be decoded into a struct
//! ```
//!
//! JSON bodies are a separate go path with their own offsets and are not
//! handled here (see the follow-up issue linked from #1967).

use algo_types::{strict_unknown_fields, SignedTransaction};
use rmpv::Value;

/// go's response for a msgpack simulate body that its strict msgpack decode rejects.
pub const GO_MSGPACK_REJECTION: &str = "failed to decode object: json decode error [pos 1]: only encoded map or array can be decoded into a struct";

/// Keys of go's `PreEncodedSimulateRequest`.
const REQUEST_KEYS: &[&str] = &[
    "txn-groups",
    "round",
    "allow-empty-signatures",
    "allow-more-logging",
    "allow-unnamed-resources",
    "extra-opcode-budget",
    "exec-trace-config",
    "fix-signers",
];
/// Keys of go's `simulation.ExecTraceConfig`.
const TRACE_CONFIG_KEYS: &[&str] = &["enable", "stack-change", "scratch-change", "state-change"];

/// The `(key, value)` pairs of `pairs`, or `None` when any key is not one of
/// `allowed` (or not a string).
fn map_keys_within<'a>(
    pairs: &'a [(Value, Value)],
    allowed: &[&str],
) -> Option<Vec<(&'a str, &'a Value)>> {
    pairs
        .iter()
        .map(|(k, v)| match k.as_str() {
            Some(name) if allowed.contains(&name) => Some((name, v)),
            _ => None,
        })
        .collect()
}

fn signed_txn_is_valid(stxn: &Value) -> bool {
    let mut bytes = Vec::new();
    if rmpv::encode::write_value(&mut bytes, stxn).is_err() {
        return false;
    }
    // Synchronous: the strict mode is thread-local and never held across an await.
    let _strict = strict_unknown_fields(&bytes);
    let mut cursor = &bytes[..];
    SignedTransaction::decode_from_reader(&mut cursor).is_ok() && cursor.is_empty()
}

fn group_is_valid(group: &Value) -> bool {
    let Some(pairs) = group.as_map() else {
        return false;
    };
    let Some(fields) = map_keys_within(pairs, &["txns"]) else {
        return false;
    };
    fields.iter().all(|(_, txns)| match txns.as_array() {
        Some(list) => list.iter().all(signed_txn_is_valid),
        None => txns.is_nil(),
    })
}

fn request_is_valid(pairs: &[(Value, Value)]) -> bool {
    let Some(fields) = map_keys_within(pairs, REQUEST_KEYS) else {
        return false;
    };
    fields.iter().all(|(name, v)| match *name {
        "txn-groups" => match v.as_array() {
            Some(groups) => groups.iter().all(group_is_valid),
            None => v.is_nil(),
        },
        "exec-trace-config" => match v.as_map() {
            Some(p) => map_keys_within(p, TRACE_CONFIG_KEYS).is_some(),
            None => v.is_nil(),
        },
        _ => true,
    })
}

/// `Some(go's text)` when `body` is a msgpack map that go's strict msgpack
/// decode of a `PreEncodedSimulateRequest` would reject; `None` when it
/// would accept it, or when the body is not a msgpack map at all (JSON text
/// and garbage keep their existing handling).
pub fn go_msgpack_rejection(body: &[u8]) -> Option<&'static str> {
    let mut rd = body;
    let value = rmpv::decode::read_value(&mut rd).ok()?;
    let pairs = value.as_map()?;
    if request_is_valid(pairs) {
        None
    } else {
        Some(GO_MSGPACK_REJECTION)
    }
}

/// A msgpack simulate request split the way the handler needs it.
pub struct DecodedMsgpackRequest {
    /// The request with every transaction replaced by `null` (the group and
    /// transaction counts are preserved for the size checks).
    pub request: crate::models::SimulateRequest,
    /// The msgpack bytes of each `SignedTxn`, per group, binary fields intact.
    pub raw_txns: Vec<Vec<Vec<u8>>>,
}

/// Decode a msgpack `SimulateRequest` without routing transactions through
/// `serde_json::Value`, which cannot hold a msgpack `bin` (issue #1968: every
/// real request has binary addresses and signatures). `None` when `body` is
/// not a msgpack map or does not fit the request model, so JSON text keeps
/// its own path.
pub fn decode_msgpack_request(body: &[u8]) -> Option<DecodedMsgpackRequest> {
    let mut rd = body;
    let value = rmpv::decode::read_value(&mut rd).ok()?;
    let Value::Map(pairs) = value else {
        return None;
    };
    let mut raw_txns: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut stripped = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        if k.as_str() != Some("txn-groups") {
            stripped.push((k, v));
            continue;
        }
        let Value::Array(groups) = v else {
            stripped.push((k, v));
            continue;
        };
        let mut new_groups = Vec::with_capacity(groups.len());
        for group in groups {
            let Value::Map(gpairs) = group else {
                new_groups.push(group);
                continue;
            };
            let mut raw_group = Vec::new();
            let mut new_gpairs = Vec::with_capacity(gpairs.len());
            for (gk, gv) in gpairs {
                match (gk.as_str() == Some("txns"), gv) {
                    (true, Value::Array(txns)) => {
                        for t in &txns {
                            let mut bytes = Vec::new();
                            rmpv::encode::write_value(&mut bytes, t).ok()?;
                            raw_group.push(bytes);
                        }
                        new_gpairs.push((gk, Value::Array(vec![Value::Nil; txns.len()])));
                    }
                    (_, gv) => new_gpairs.push((gk, gv)),
                }
            }
            raw_txns.push(raw_group);
            new_groups.push(Value::Map(new_gpairs));
        }
        stripped.push((k, Value::Array(new_groups)));
    }
    let request = rmpv::ext::from_value::<crate::models::SimulateRequest>(Value::Map(stripped)).ok()?;
    Some(DecodedMsgpackRequest { request, raw_txns })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> Value {
        Value::String(x.into())
    }
    fn bin(b: &[u8]) -> Value {
        Value::Binary(b.to_vec())
    }
    fn map(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (s(k), v)).collect())
    }
    fn txn(extra: Vec<(&str, Value)>) -> Value {
        let mut p = vec![
            ("amt", Value::from(1000u64)),
            ("fee", Value::from(1000u64)),
            ("fv", Value::from(100u64)),
            ("gh", bin(&[3u8; 32])),
            ("lv", Value::from(1100u64)),
            ("rcv", bin(&[2u8; 32])),
            ("snd", bin(&[1u8; 32])),
            ("type", s("pay")),
        ];
        p.extend(extra);
        map(p)
    }
    fn stxn(top_extra: Vec<(&str, Value)>, txn_extra: Vec<(&str, Value)>) -> Value {
        let mut p = vec![("sig", bin(&[7u8; 64])), ("txn", txn(txn_extra))];
        p.extend(top_extra);
        map(p)
    }
    fn request(
        stxns: Vec<Value>,
        group_extra: Vec<(&str, Value)>,
        top_extra: Vec<(&str, Value)>,
    ) -> Vec<u8> {
        let mut g = vec![("txns", Value::Array(stxns))];
        g.extend(group_extra);
        let mut p = vec![("txn-groups", Value::Array(vec![map(g)]))];
        p.extend(top_extra);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &map(p)).unwrap();
        out
    }

    #[test]
    fn a_clean_request_is_accepted() {
        let ok = request(vec![stxn(vec![], vec![])], vec![], vec![]);
        assert_eq!(go_msgpack_rejection(&ok), None);
    }

    #[test]
    fn every_known_request_key_is_accepted() {
        let top = vec![
            ("round", Value::from(5u64)),
            ("allow-empty-signatures", Value::Boolean(true)),
            ("allow-more-logging", Value::Boolean(true)),
            ("allow-unnamed-resources", Value::Boolean(true)),
            ("extra-opcode-budget", Value::from(700u64)),
            ("fix-signers", Value::Boolean(true)),
            (
                "exec-trace-config",
                map(vec![
                    ("enable", Value::Boolean(true)),
                    ("stack-change", Value::Boolean(true)),
                    ("scratch-change", Value::Boolean(true)),
                    ("state-change", Value::Boolean(true)),
                ]),
            ),
        ];
        let ok = request(vec![stxn(vec![], vec![])], vec![], top);
        assert_eq!(go_msgpack_rejection(&ok), None);
    }

    /// Each body below is rejected by a live go-algorand v5.0.3-stable node with
    /// exactly `GO_MSGPACK_REJECTION`.
    #[test]
    fn unknown_keys_at_every_level_get_gos_fixed_text() {
        let z = || ("zzz", Value::from(1u64));
        let bodies = [
            (
                "request",
                request(vec![stxn(vec![], vec![])], vec![], vec![z()]),
            ),
            (
                "group",
                request(vec![stxn(vec![], vec![])], vec![z()], vec![]),
            ),
            (
                "signed txn",
                request(vec![stxn(vec![z()], vec![])], vec![], vec![]),
            ),
            (
                "txn",
                request(vec![stxn(vec![], vec![z()])], vec![], vec![]),
            ),
            (
                "hgi",
                request(
                    vec![stxn(vec![("hgi", Value::Boolean(true))], vec![])],
                    vec![],
                    vec![],
                ),
            ),
            (
                "trace config",
                request(
                    vec![stxn(vec![], vec![])],
                    vec![],
                    vec![("exec-trace-config", map(vec![z()]))],
                ),
            ),
        ];
        for (name, body) in bodies {
            assert_eq!(
                go_msgpack_rejection(&body),
                Some(GO_MSGPACK_REJECTION),
                "{name}"
            );
        }
    }

    #[test]
    fn json_text_and_garbage_are_left_to_the_existing_handling() {
        assert_eq!(go_msgpack_rejection(br#"{"txn-groups":[],"zzz":1}"#), None);
        assert_eq!(go_msgpack_rejection(b""), None);
        assert_eq!(go_msgpack_rejection(&[0xc1, 0xff]), None);
        assert_eq!(go_msgpack_rejection(&[0x91, 0x01]), None); // an array, not a map
    }

    #[test]
    fn decode_keeps_binary_transactions_and_request_fields() {
        let st = stxn(vec![], vec![]);
        let body = request(
            vec![st.clone(), st.clone()],
            vec![],
            vec![("round", Value::from(77u64)), ("allow-empty-signatures", Value::Boolean(true))],
        );
        let d = decode_msgpack_request(&body).expect("decodes");
        assert_eq!(d.request.round, Some(77));
        assert_eq!(d.request.allow_empty_signatures, Some(true));
        assert_eq!(d.request.txn_groups.len(), 1);
        assert_eq!(d.request.txn_groups[0].txns.len(), 2);
        assert_eq!(d.raw_txns.len(), 1);
        assert_eq!(d.raw_txns[0].len(), 2);
        // the transaction bytes are the original msgpack, binary fields intact
        let mut want = Vec::new();
        rmpv::encode::write_value(&mut want, &st).unwrap();
        assert_eq!(d.raw_txns[0][0], want);
        let back: SignedTransaction = rmp_serde::from_slice(&d.raw_txns[0][0]).expect("typed decode");
        assert_eq!(back.txn.txn_type, "pay");
        assert_eq!(back.sig, [7u8; 64]);
    }

    #[test]
    fn decode_is_none_for_json_text_and_non_maps() {
        assert!(decode_msgpack_request(br#"{"txn-groups":[]}"#).is_none());
        assert!(decode_msgpack_request(b"").is_none());
        assert!(decode_msgpack_request(&[0x91, 0x01]).is_none());
    }

    #[test]
    fn a_nested_unknown_key_deep_in_the_transaction_is_found() {
        let boxes = Value::Array(vec![map(vec![("zzz", Value::from(1u64))])]);
        let body = request(vec![stxn(vec![], vec![("apbx", boxes)])], vec![], vec![]);
        assert_eq!(go_msgpack_rejection(&body), Some(GO_MSGPACK_REJECTION));
    }
}
