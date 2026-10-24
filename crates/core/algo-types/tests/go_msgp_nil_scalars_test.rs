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

//! Issue #2065 item 1: go's generated decoders read every integer with
//! `msgp.ReadUint64Bytes` / `ReadInt64Bytes`, every bool with `ReadBoolBytes`
//! and every struct/map header with `ReadMapHeaderBytes` -- all of which map
//! a msgpack `nil` (0xc0) to the zero value (algorand/msgp v1.1.64
//! `read_bytes.go`). The shared hand-written readers must do the same.
//! See `docs/BYTES_DECODE_PARITY.md`.

use algo_types::{BlockHeader, SignedTransaction, Transaction};

const NIL: u8 = 0xc0;

fn fixstr(s: &str) -> Vec<u8> {
    let mut v = vec![0xa0 | s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

fn map(entries: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut v = vec![0x80 | entries.len() as u8];
    for (k, val) in entries {
        v.extend(fixstr(k));
        v.extend(val);
    }
    v
}

#[test]
fn nil_uint64_fields_decode_as_zero() {
    let b = map(vec![
        ("type", fixstr("pay")),
        ("snd", [vec![0xc4, 32], vec![1u8; 32]].concat()),
        ("fv", vec![5]),
        ("lv", vec![7]),
        ("fee", vec![NIL]),
        ("amt", vec![NIL]),
    ]);
    let t = Transaction::decode_from_reader(&mut &b[..]).expect("nil uint must decode as 0");
    assert_eq!(t.fee, 0);
    assert_eq!(t.amount, 0);
    assert_eq!(t.first_valid.0, 5);
    assert_eq!(t.last_valid.0, 7);
}

#[test]
fn nil_struct_header_is_not_a_type_error() {
    // go: ReadMapHeaderBytes(nil) -> sz 0, isnil -> struct zeroed. The empty
    // `txn` then trips the (separate) required-field check, but the nil
    // header itself must not be reported as a bad map marker.
    let b = map(vec![("txn", vec![NIL])]);
    if let Err(e) = SignedTransaction::decode_from_reader(&mut &b[..]) {
        let m = e.to_string();
        assert!(!m.contains("read_map_len"), "nil map header rejected: {m}");
    }
}

#[test]
fn nil_header_scalars_decode() {
    let b = map(vec![("rnd", vec![NIL]), ("ts", vec![NIL])]);
    let h = BlockHeader::decode_from_reader(&mut &b[..]);
    assert!(h.is_ok(), "nil rnd/ts must decode as 0: {:?}", h.err());
}
