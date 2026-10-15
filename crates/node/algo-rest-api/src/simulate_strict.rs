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
//! handled here (see #1971). They are decoded here only in go's JSON form
//! (see [`parse_json_request`], issue #1972).

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

/// Strictly decode one `SignedTxn` value; its msgpack bytes when go's
/// strict decode would accept it.
fn strict_signed_txn_bytes(stxn: &Value) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, stxn).ok()?;
    // Synchronous: the strict mode is thread-local and never held across an await.
    let strict = strict_unknown_fields(&bytes);
    let mut cursor = &bytes[..];
    let ok = SignedTransaction::decode_from_reader(&mut cursor).is_ok() && cursor.is_empty();
    drop(strict);
    ok.then_some(bytes)
}

/// A msgpack simulate request split the way the handler needs it.
pub struct DecodedMsgpackRequest {
    /// The request with every transaction replaced by `null` (the group and
    /// transaction counts are preserved for the size checks).
    pub request: crate::models::SimulateRequest,
    /// The msgpack bytes of each `SignedTxn`, per group (aligned with
    /// `request.txn_groups`), binary fields intact.
    pub raw_txns: Vec<Vec<Vec<u8>>>,
}

/// The outcome of parsing a simulate body as go's strict msgpack decode would.
pub enum MsgpackSimulate {
    /// Not a msgpack map (JSON text, garbage): the JSON path handles it.
    NotMsgpack,
    /// A msgpack map go's strict decode rejects: an unknown key at any level,
    /// a field of the wrong type, a malformed transaction. The answer is
    /// [`GO_MSGPACK_REJECTION`].
    Rejected,
    Decoded(DecodedMsgpackRequest),
}

/// Parse and strictly validate a msgpack `SimulateRequest` in one pass.
///
/// Transactions are never routed through `serde_json::Value`, which cannot
/// hold a msgpack `bin` (issue #1968: every real request has binary
/// addresses and signatures); each keeps its own msgpack bytes.
pub fn parse_msgpack_request(body: &[u8]) -> MsgpackSimulate {
    let mut rd = body;
    let Ok(Value::Map(pairs)) = rmpv::decode::read_value(&mut rd) else {
        return MsgpackSimulate::NotMsgpack;
    };
    parse_request_pairs(pairs).map_or(MsgpackSimulate::Rejected, MsgpackSimulate::Decoded)
}

fn parse_request_pairs(pairs: Vec<(Value, Value)>) -> Option<DecodedMsgpackRequest> {
    map_keys_within(&pairs, REQUEST_KEYS)?;
    let mut raw_txns: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut stripped = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        match (k.as_str(), v) {
            (Some("txn-groups"), Value::Array(groups)) => {
                let mut new_groups = Vec::with_capacity(groups.len());
                for group in groups {
                    let Value::Map(gpairs) = group else {
                        return None;
                    };
                    map_keys_within(&gpairs, &["txns"])?;
                    let mut raw_group = Vec::new();
                    let mut new_gpairs = Vec::with_capacity(gpairs.len());
                    for (gk, gv) in gpairs {
                        match gv {
                            Value::Array(txns) => {
                                for t in &txns {
                                    raw_group.push(strict_signed_txn_bytes(t)?);
                                }
                                new_gpairs.push((gk, Value::Array(vec![Value::Nil; txns.len()])));
                            }
                            other => new_gpairs.push((gk, other)),
                        }
                    }
                    raw_txns.push(raw_group);
                    new_groups.push(Value::Map(new_gpairs));
                }
                stripped.push((k, Value::Array(new_groups)));
            }
            (Some("exec-trace-config"), Value::Map(cfg)) => {
                map_keys_within(&cfg, TRACE_CONFIG_KEYS)?;
                stripped.push((k, Value::Map(cfg)));
            }
            (_, v) => stripped.push((k, v)),
        }
    }
    let request =
        rmpv::ext::from_value::<crate::models::SimulateRequest>(Value::Map(stripped)).ok()?;
    // The typed model is the final word on shape: group and transaction
    // counts must line up with the raw bytes collected above.
    let aligned = request.txn_groups.len() == raw_txns.len()
        && request
            .txn_groups
            .iter()
            .zip(&raw_txns)
            .all(|(g, r)| g.txns.len() == r.len());
    aligned.then_some(DecodedMsgpackRequest { request, raw_txns })
}

/// JSON string leaves that are text in go's structs (`string`, not `[]byte`).
const TEXT_KEYS: &[&str] = &["type", "gen", "an", "un", "au"];

/// Decode a checksummed 58-character Algorand address to its 32 bytes.
fn address_from_base32(text: &str) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha512_256};
    let raw = data_encoding::BASE32_NOPAD.decode(text.as_bytes()).ok()?;
    if raw.len() != 36 {
        return None;
    }
    let (addr, checksum) = raw.split_at(32);
    if Sha512_256::digest(addr)[28..32] != *checksum {
        return None;
    }
    addr.try_into().ok()
}

/// Convert go's JSON encoding of a request (`protocol.JSONStrictHandle`:
/// addresses as checksummed base32, other `[]byte` as base64, text as text,
/// the same short keys as msgpack) into the msgpack value tree the strict
/// parser works on. The inverse of `block_json`'s key-driven rendering, so
/// the same key tables decide which strings are addresses. `None` for
/// anything that is not go's JSON form (a string that is not valid base64 or
/// a checksummed address where bytes are expected, a non-integral number).
pub fn json_to_msgpack(v: &serde_json::Value, key: &str, parent: &str) -> Option<Value> {
    use base64::Engine;
    Some(match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                Value::from(n.as_i64()?)
            }
        }
        serde_json::Value::String(text) => {
            if TEXT_KEYS.contains(&key) {
                Value::String(text.as_str().into())
            } else if crate::block_json::ADDRESS_KEYS.contains(&key)
                || (crate::block_json::APAR_ADDRESS_KEYS.contains(&key) && parent == "apar")
            {
                Value::Binary(address_from_base32(text)?.to_vec())
            } else {
                Value::Binary(
                    base64::engine::general_purpose::STANDARD
                        .decode(text.as_bytes())
                        .ok()?,
                )
            }
        }
        serde_json::Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| json_to_msgpack(i, key, parent))
                .collect::<Option<Vec<_>>>()?,
        ),
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, val)| Some((Value::String(k.as_str().into()), json_to_msgpack(val, k, key)?)))
                .collect::<Option<Vec<_>>>()?,
        ),
    })
}

/// Parse a JSON simulate body written in go's JSON form (issue #1972) with
/// the same strict pipeline as a msgpack body. `None` when the body is not
/// JSON, is not go's JSON form, or the strict pipeline rejects it; the
/// caller then keeps its older serde-form handling.
pub fn parse_json_request(body: &[u8]) -> Option<DecodedMsgpackRequest> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let serde_json::Value::Object(map) = &json else {
        return None;
    };
    let pairs = map
        .iter()
        .map(|(k, v)| Some((Value::String(k.as_str().into()), json_to_msgpack(v, k, "")?)))
        .collect::<Option<Vec<_>>>()?;
    parse_request_pairs(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejection(body: &[u8]) -> Option<&'static str> {
        match parse_msgpack_request(body) {
            MsgpackSimulate::Rejected => Some(GO_MSGPACK_REJECTION),
            _ => None,
        }
    }
    fn decode(body: &[u8]) -> Option<DecodedMsgpackRequest> {
        match parse_msgpack_request(body) {
            MsgpackSimulate::Decoded(d) => Some(d),
            _ => None,
        }
    }

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
        assert_eq!(rejection(&ok), None);
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
        assert_eq!(rejection(&ok), None);
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
                rejection(&body),
                Some(GO_MSGPACK_REJECTION),
                "{name}"
            );
        }
    }

    #[test]
    fn json_text_and_garbage_are_left_to_the_existing_handling() {
        assert_eq!(rejection(br#"{"txn-groups":[],"zzz":1}"#), None);
        assert_eq!(rejection(b""), None);
        assert_eq!(rejection(&[0xc1, 0xff]), None);
        assert_eq!(rejection(&[0x91, 0x01]), None); // an array, not a map
    }

    #[test]
    fn decode_keeps_binary_transactions_and_request_fields() {
        let st = stxn(vec![], vec![]);
        let body = request(
            vec![st.clone(), st.clone()],
            vec![],
            vec![("round", Value::from(77u64)), ("allow-empty-signatures", Value::Boolean(true))],
        );
        let d = decode(&body).expect("decodes");
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
        assert!(decode(br#"{"txn-groups":[]}"#).is_none());
        assert!(decode(b"").is_none());
        assert!(decode(&[0x91, 0x01]).is_none());
    }

    /// go's strict msgpack decode also fails on a wrongly typed field or a
    /// malformed group, and the JSON fallback then gives the same fixed text.
    #[test]
    fn wrongly_typed_fields_and_malformed_groups_are_rejected_too() {
        let st = stxn(vec![], vec![]);
        let bad_round = request(vec![st.clone()], vec![], vec![("round", s("seven"))]);
        assert_eq!(rejection(&bad_round), Some(GO_MSGPACK_REJECTION));
        let neg_budget = request(
            vec![st.clone()],
            vec![],
            vec![("extra-opcode-budget", Value::from(-5i64))],
        );
        assert_eq!(rejection(&neg_budget), None, "a signed int is a valid Go int");
        let mut out = Vec::new();
        let not_a_map_group = map(vec![("txn-groups", Value::Array(vec![Value::Nil]))]);
        rmpv::encode::write_value(&mut out, &not_a_map_group).unwrap();
        assert_eq!(rejection(&out), Some(GO_MSGPACK_REJECTION));
    }

    #[test]
    fn raw_transactions_stay_aligned_with_the_groups_across_several_groups() {
        let g = |n: usize| map(vec![("txns", Value::Array(vec![stxn(vec![], vec![]); n]))]);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &map(vec![("txn-groups", Value::Array(vec![g(1), g(3), g(2)]))]),
        )
        .unwrap();
        let d = decode(&body).expect("decodes");
        let counts: Vec<usize> = d.raw_txns.iter().map(Vec::len).collect();
        assert_eq!(counts, vec![1, 3, 2]);
        let model: Vec<usize> = d.request.txn_groups.iter().map(|g| g.txns.len()).collect();
        assert_eq!(model, counts);
    }

    /// go's JSON form of the same transaction `stxn()` builds in msgpack:
    /// addresses as checksummed base32, other bytes as base64, text as text.
    fn go_json_stxn() -> serde_json::Value {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        serde_json::json!({
            "sig": b64(&[7u8; 64]),
            "txn": {
                "type": "pay",
                "snd": crate::block_json::address_to_base32(&[1u8; 32]),
                "rcv": crate::block_json::address_to_base32(&[2u8; 32]),
                "amt": 1000, "fee": 1000, "fv": 100, "lv": 1100,
                "gh": b64(&[3u8; 32]),
            }
        })
    }

    fn json_request(stxns: Vec<serde_json::Value>, extra: serde_json::Value) -> Vec<u8> {
        let mut req = serde_json::json!({ "txn-groups": [{ "txns": stxns }] });
        if let (Some(r), Some(e)) = (req.as_object_mut(), extra.as_object()) {
            r.extend(e.clone());
        }
        serde_json::to_vec(&req).unwrap()
    }

    /// Issue #1972: go's JSON form of a SignedTxn (base64 `sig`, address
    /// strings) decodes to exactly the transaction the msgpack form does.
    #[test]
    fn go_json_form_decodes_to_the_same_transaction_as_msgpack() {
        let from_json = parse_json_request(&json_request(
            vec![go_json_stxn()],
            serde_json::json!({"round": 9, "allow-empty-signatures": true}),
        ))
        .expect("go's JSON form decodes");
        let from_msgpack = decode(&request(vec![stxn(vec![], vec![])], vec![], vec![])).unwrap();

        let a: SignedTransaction = rmp_serde::from_slice(&from_json.raw_txns[0][0]).unwrap();
        let b: SignedTransaction = rmp_serde::from_slice(&from_msgpack.raw_txns[0][0]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.sig, [7u8; 64]);
        assert_eq!(a.txn.sender.0, [1u8; 32]);
        assert_eq!(a.txn.receiver.0, [2u8; 32]);
        assert_eq!(a.txn.txn_type, "pay");
        assert_eq!(from_json.request.round, Some(9));
        assert_eq!(from_json.request.allow_empty_signatures, Some(true));
    }

    #[test]
    fn json_text_keys_stay_text_and_other_strings_are_bytes() {
        let t = |v: serde_json::Value, key: &str| json_to_msgpack(&v, key, "").unwrap();
        assert_eq!(t(serde_json::json!("pay"), "type"), Value::String("pay".into()));
        assert_eq!(t(serde_json::json!("My Asset"), "an"), Value::String("My Asset".into()));
        assert_eq!(t(serde_json::json!("AQID"), "note"), Value::Binary(vec![1, 2, 3]));
        // asset-params letters are addresses only under `apar`
        let addr = crate::block_json::address_to_base32(&[9u8; 32]);
        assert_eq!(
            json_to_msgpack(&serde_json::json!(addr), "m", "apar").unwrap(),
            Value::Binary(vec![9u8; 32])
        );
        assert_eq!(json_to_msgpack(&serde_json::json!("AQID"), "m", "").unwrap(), Value::Binary(vec![1, 2, 3]));
    }

    #[test]
    fn json_that_is_not_go_form_is_none() {
        // an address with a bad checksum, bytes that are not base64, a float
        let bad_addr = "A".repeat(58);
        assert!(json_to_msgpack(&serde_json::json!(bad_addr), "snd", "txn").is_none());
        assert!(json_to_msgpack(&serde_json::json!("not base64!"), "sig", "").is_none());
        assert!(json_to_msgpack(&serde_json::json!(1.5), "amt", "").is_none());
        // Rust's own serde form (numbers for bytes) is not go's JSON form either
        let serde_form = serde_json::to_vec(&serde_json::json!({
            "txn-groups": [{"txns": [{"sig": vec![0u8; 64]}]}]
        }))
        .unwrap();
        assert!(parse_json_request(&serde_form).is_none());
        assert!(parse_json_request(b"[]").is_none());
        assert!(parse_json_request(b"not json").is_none());
    }

    #[test]
    fn a_nested_unknown_key_deep_in_the_transaction_is_found() {
        let boxes = Value::Array(vec![map(vec![("zzz", Value::from(1u64))])]);
        let body = request(vec![stxn(vec![], vec![("apbx", boxes)])], vec![], vec![]);
        assert_eq!(rejection(&body), Some(GO_MSGPACK_REJECTION));
    }
}
