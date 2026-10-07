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

//! Untrusted-input guard (PR #1742 review): a `SignedTransaction` decoded
//! through plain serde (gossip, REST submit, tools) must stay strict. Only the
//! `EvalDelta.itx` read path (`algo_ledger::eval_delta::parse_inner_txns`) is
//! lenient about go's omitted zero-valued `txn` / `type` / `snd`.

use algo_types::SignedTransaction;

fn decode(bytes: &[u8]) -> Result<SignedTransaction, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}

#[test]
fn signed_txn_without_txn_map_is_rejected() {
    // {} -- no `txn`.
    assert!(decode(&[0x80]).is_err());
}

#[test]
fn signed_txn_with_empty_txn_map_is_rejected() {
    // {"txn": {}} -- no `type`, no `snd`.
    assert!(decode(&[0x81, 0xa3, b't', b'x', b'n', 0x80]).is_err());
}

#[test]
fn signed_txn_without_type_is_rejected() {
    // {"txn": {"snd": bin32}}
    let mut b = vec![
        0x81, 0xa3, b't', b'x', b'n', 0x81, 0xa3, b's', b'n', b'd', 0xc4, 0x20,
    ];
    b.extend_from_slice(&[7u8; 32]);
    assert!(decode(&b).is_err());
}

#[test]
fn signed_txn_without_snd_is_rejected() {
    // {"txn": {"type": "pay"}}
    let b = [
        0x81, 0xa3, b't', b'x', b'n', 0x81, 0xa4, b't', b'y', b'p', b'e', 0xa3, b'p', b'a', b'y',
    ];
    assert!(decode(&b).is_err());
}
