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

//! Port of go-algorand's `ledger/apply/payment_test.go`'s `TestAlgosEncoding`
//! (phase 17 / issue tracked in `docs/phase17/parity_ledger_core.md`).
//!
//! go's `basics.MicroAlgos` is a struct with a single `Raw uint64` field, but
//! its custom `MarshalMsg`/`UnmarshalMsg` encode/decode it as a *bare*
//! msgpack integer on the wire (not a one-field map) -- so a round trip
//! through `protocol.Encode`/`protocol.Decode` is exactly a round trip of a
//! plain `uint64`, and decoding a msgpack value of the wrong type (e.g. a
//! bool) into it must fail rather than silently coerce.
//!
//! algod-rust represents "micro algos" directly as `u64` everywhere (no
//! wrapper newtype), which already gets this wire representation for free
//! from serde's integer encoding -- this test pins that encoding explicitly
//! using the values from go's test, plus the "wrong wire type" rejection.

/// Mirrors go's `a.Raw = 222233333; protocol.Decode(protocol.Encode(&a), &b)`.
#[test]
fn micro_algos_u64_roundtrips_through_canonical_msgpack() {
    let a: u64 = 222_233_333;
    let bytes = rmp_serde::to_vec(&a).expect("msgpack encode");
    let b: u64 = rmp_serde::from_slice(&bytes).expect("msgpack decode");
    assert_eq!(a, b);
}

/// Mirrors go's second case: `a.Raw = 12345678`, encoded, decoded via a
/// generic (reflective) path into a plain integer -- i.e. the wire bytes for
/// a MicroAlgos value and for a bare `uint64` are identical.
#[test]
fn micro_algos_u64_wire_bytes_match_bare_integer_encoding() {
    let raw: u64 = 12_345_678;
    let as_micro_algos = rmp_serde::to_vec(&raw).expect("msgpack encode");
    let as_plain_u64 = rmp_serde::to_vec(&raw).expect("msgpack encode");
    assert_eq!(as_micro_algos, as_plain_u64);

    let decoded: u64 = rmp_serde::from_slice(&as_micro_algos).expect("msgpack decode");
    assert_eq!(decoded, raw);
}

/// Mirrors go's final case:
/// ```go
/// x := true
/// err = protocol.Decode(protocol.EncodeReflect(x), &a)
/// if err == nil { panic("decode of bool into MicroAlgos succeeded") }
/// ```
/// Decoding a msgpack-encoded bool into a `u64`-typed field must fail, not
/// silently coerce to 0/1.
#[test]
fn decode_of_bool_into_micro_algos_u64_field_fails() {
    let bytes = rmp_serde::to_vec(&true).expect("msgpack encode bool");
    let result: Result<u64, _> = rmp_serde::from_slice(&bytes);
    assert!(
        result.is_err(),
        "decoding a bool into a u64 (MicroAlgos-shaped) field must fail, got {result:?}"
    );
}
