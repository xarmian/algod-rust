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

//! Msgpack roundtrip coverage for [`algo_network::EncodedBlockCert`]
//! (Phase 17, issue #827 theme 5) — the algod-rust analogue of
//! go-algorand's `TestMarshalUnmarshalEncodedBlockCert` /
//! `TestRandomizedEncodingEncodedBlockCert`
//! (`rpcs/msgp_gen_test.go`), which round-trip `rpcs.EncodedBlockCert`
//! (a `{block, cert}` pair — the block-sync/catchup wire format) through
//! its generated msgp codec.
//!
//! `crates/node/algo-network/src/block_cert.rs` already unit-tests
//! `Certificate`'s msgpack roundtrip in isolation
//! (`certificate_msgpack_round_trip`, `default_certificate_msgpack_round_trip`),
//! but nothing previously exercised the full `EncodedBlockCert` — which
//! requires an actual `Block`, not just a `Certificate` — through
//! msgpack. This file closes that gap by decoding the real `{block, cert}`
//! fixtures already checked in for `algo-rest-api`'s block-JSON
//! conformance tests (each one go-algorand v4.6.0-stable's raw block
//! response) and round-tripping them.

use algo_network::block_cert::EncodedBlockCert;

/// Decode `msgpack` into `EncodedBlockCert`, re-encode it, decode again,
/// and assert the two decoded values are equal — proving the type
/// round-trips real `{block, cert}` payloads without loss.
fn check_roundtrip(name: &str, msgpack: &[u8]) {
    let decoded: EncodedBlockCert =
        rmp_serde::from_slice(msgpack).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    let re_encoded = rmp_serde::to_vec_named(&decoded)
        .unwrap_or_else(|e| panic!("{name}: re-encode failed: {e}"));
    let re_decoded: EncodedBlockCert = rmp_serde::from_slice(&re_encoded)
        .unwrap_or_else(|e| panic!("{name}: re-decode failed: {e}"));
    assert_eq!(
        decoded, re_decoded,
        "{name}: EncodedBlockCert must round-trip through msgpack without loss"
    );
    assert_eq!(
        decoded.block.round, re_decoded.block.round,
        "{name}: round must survive round-trip"
    );
}

macro_rules! roundtrip_test {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            let msgpack = include_bytes!(concat!(
                "../../algo-rest-api/tests/fixtures/block_json/",
                $name,
                ".msgpack"
            ));
            check_roundtrip($name, msgpack);
        }
    };
}

roundtrip_test!(encoded_block_cert_roundtrip_pay_block1, "block1");
roundtrip_test!(encoded_block_cert_roundtrip_pay_block_1, "block_1");
roundtrip_test!(encoded_block_cert_roundtrip_acfg_block_2, "block_2");
roundtrip_test!(encoded_block_cert_roundtrip_axfer_block_3, "block_3");
roundtrip_test!(encoded_block_cert_roundtrip_afrz_block_5, "block_5");
roundtrip_test!(encoded_block_cert_roundtrip_pay_block_9, "block_9");
roundtrip_test!(
    encoded_block_cert_roundtrip_appl_eval_delta,
    "synthetic_appl"
);
