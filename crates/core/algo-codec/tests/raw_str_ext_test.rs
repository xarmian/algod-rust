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
fn stale_flag_from_direct_serde_does_not_affect_wrapper() {
    use algo_types::serde_bytes_array::serde_raw_str::{replace_ext_emitted, take_ext_emitted};
    take_ext_emitted();
    // A direct serde call (no wrapper) leaks the flag.
    let _ = rmp_serde::to_vec_named(&params(&[0xff])).unwrap();
    // Wrapper on valid data: plain bytes, and the stale value is restored,
    // not consumed.
    let ok = to_vec_named_str_preserving(&params(b"x")).unwrap();
    assert_eq!(ok, rmp_serde::to_vec_named(&params(b"x")).unwrap());
    assert!(replace_ext_emitted(true), "stale flag restored");
    // Wrapper on invalid data still rewrites correctly with a stale flag set.
    let bad = to_vec_named_str_preserving(&params(&[0xff])).unwrap();
    assert!(!bad.contains(&0x5a) || bad.windows(2).all(|w| w != [0xd5, 0x5a]));
    assert!(take_ext_emitted(), "stale flag restored again");
    assert!(!take_ext_emitted());
}

#[test]
fn hand_decoders_reject_the_placeholder_ext() {
    // map{un: fixext2(0x5a, ff fe)} -- what a leaked placeholder looks like.
    for key in [&b"un"[..], b"an", b"au"] {
        let mut b = vec![0x81, 0xa2];
        b.extend_from_slice(key);
        b.extend_from_slice(&[0xd5, 0x5a, 0xff, 0xfe]);
        assert!(
            AssetParams::decode_from_bytes(&b).is_err(),
            "hand decoder must reject ext in {key:?}"
        );
        // ... and a serde decode outside the trusted scope rejects it too.
        assert!(rmp_serde::from_slice::<AssetParams>(&b).is_err());
    }
}

#[test]
fn block_response_with_non_utf8_asset_name_matches_canonical_field() {
    let bytes = include_bytes!("fixtures/block1.msgpack");
    let mut br = algo_codec::decode_block_response(bytes).unwrap();
    let apar = params(&[0xff, 0xfe]);
    br.block.payset[0].txn.asset_params = Some(apar.clone());

    let out = to_vec_named_str_preserving(&br).unwrap();
    // go's bytes for the field, per the canonical block encoder.
    let field = [0x81, 0xa2, b'u', b'n', 0xa2, 0xff, 0xfe];
    let canon = algo_codec::canonical_encode_block(&br.block);
    assert!(canon.windows(field.len()).any(|w| w == &field[..]));
    assert!(
        out.windows(field.len()).any(|w| w == &field[..]),
        "wrapper output must embed the canonical apar bytes (str, not ext/bin)"
    );
    // No placeholder survives, and the hand decoder reads the bytes back.
    assert!(!out.windows(2).any(|w| w == [0xd5, 0x5a]));
    let back = algo_codec::decode_block_response_fast(&out).unwrap();
    assert_eq!(
        back.block.payset[0]
            .txn
            .asset_params
            .as_ref()
            .unwrap()
            .unit_name,
        vec![0xff, 0xfe]
    );
}
