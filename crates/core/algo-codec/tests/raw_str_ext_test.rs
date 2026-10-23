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

//! Issue #2042: serde msgpack edges keep go's exact `str` bytes for
//! non-UTF-8 AssetParams un/an/au.

use algo_codec::to_vec_named_str_preserving;
use algo_types::AssetParams;

fn params(un: &[u8]) -> AssetParams {
    AssetParams {
        unit_name: un.to_vec(),
        ..Default::default()
    }
}

#[test]
fn valid_utf8_bytes_unchanged() {
    let p = params(b"ab");
    assert_eq!(
        to_vec_named_str_preserving(&p).unwrap(),
        rmp_serde::to_vec_named(&p).unwrap()
    );
}

#[test]
fn non_utf8_is_str_with_raw_bytes() {
    let good = to_vec_named_str_preserving(&params(b"ab")).unwrap();
    let bad = to_vec_named_str_preserving(&params(&[0xff, 0xfe])).unwrap();
    let mut expected = good.clone();
    let pos = expected.windows(2).position(|w| w == b"ab").unwrap();
    expected[pos] = 0xff;
    expected[pos + 1] = 0xfe;
    assert_eq!(bad, expected);
    // marker preceding the payload is fixstr(2) = 0xa2
    assert_eq!(bad[pos - 1], 0xa2);
}

#[test]
fn flag_does_not_leak_between_calls() {
    let _ = to_vec_named_str_preserving(&params(&[0xff])).unwrap();
    let ok = to_vec_named_str_preserving(&params(b"x")).unwrap();
    assert_eq!(ok, rmp_serde::to_vec_named(&params(b"x")).unwrap());
}
