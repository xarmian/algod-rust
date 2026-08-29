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

use algo_types::BlockResponse;

#[test]
fn decode_real_block_response() {
    let bytes = include_bytes!("fixtures/block1.msgpack");

    // Verify raw msgpack is valid
    let raw = rmpv::decode::read_value(&mut &bytes[..]).expect("raw msgpack decode failed");
    assert!(matches!(raw, rmpv::Value::Map(_)));

    // Typed decode
    let br: BlockResponse =
        rmp_serde::from_slice(bytes).expect("BlockResponse decode should succeed");

    assert_eq!(br.block.round.0, 1);
    assert!(!br.block.genesis_id.is_empty());
    assert_eq!(br.block.payset.len(), 1);
    assert_eq!(br.block.payset[0].txn.txn_type, "pay");
}

/// Decode all captured fixtures and verify basic structural properties.
macro_rules! fixture_decode_test {
    ($name:ident, $file:expr, $expected_round:expr) => {
        #[test]
        fn $name() {
            let bytes = include_bytes!(concat!("fixtures/", $file));

            // Decode
            let br: BlockResponse =
                algo_codec::decode_block_response(bytes).expect("decode should succeed");

            // Round matches expected
            assert_eq!(br.block.round.0, $expected_round, "round mismatch");

            // Header fields are populated
            assert!(!br.block.genesis_id.is_empty(), "genesis_id should be set");
            assert!(
                br.block.genesis_hash != [0u8; 32],
                "genesis_hash should be set"
            );
            assert!(
                !br.block.current_protocol.is_empty(),
                "protocol should be set"
            );

            // Round-trip: encode then decode again
            let re_encoded = algo_codec::encode_block(&br.block).expect("re-encode should succeed");
            let re_decoded =
                algo_codec::decode_block(&re_encoded).expect("re-decode should succeed");

            assert_eq!(
                re_decoded.round, br.block.round,
                "round-trip round mismatch"
            );
            assert_eq!(
                re_decoded.payset.len(),
                br.block.payset.len(),
                "round-trip txn count mismatch"
            );
            assert_eq!(
                re_decoded.genesis_id, br.block.genesis_id,
                "round-trip genesis_id mismatch"
            );
            assert_eq!(
                re_decoded.timestamp, br.block.timestamp,
                "round-trip timestamp mismatch"
            );
            assert_eq!(
                re_decoded.fee_sink, br.block.fee_sink,
                "round-trip fee_sink mismatch"
            );
            assert_eq!(
                re_decoded.rewards_pool, br.block.rewards_pool,
                "round-trip rewards_pool mismatch"
            );

            // Per-txn field round-trip
            for (i, (orig, rt)) in br
                .block
                .payset
                .iter()
                .zip(re_decoded.payset.iter())
                .enumerate()
            {
                assert_eq!(orig.txn.txn_type, rt.txn.txn_type, "txn[{i}] type mismatch");
                assert_eq!(orig.txn.sender, rt.txn.sender, "txn[{i}] sender mismatch");
                assert_eq!(orig.txn.fee, rt.txn.fee, "txn[{i}] fee mismatch");
                assert_eq!(orig.txn.amount, rt.txn.amount, "txn[{i}] amount mismatch");
                assert_eq!(
                    orig.txn.receiver, rt.txn.receiver,
                    "txn[{i}] receiver mismatch"
                );
            }
        }
    };
}

fixture_decode_test!(decode_block_1, "block_1.msgpack", 1);
fixture_decode_test!(decode_block_2, "block_2.msgpack", 2);
fixture_decode_test!(decode_block_3, "block_3.msgpack", 3);
fixture_decode_test!(decode_block_4, "block_4.msgpack", 4);
fixture_decode_test!(decode_block_5, "block_5.msgpack", 5);
fixture_decode_test!(decode_block_6_appl_create, "block_6.msgpack", 6);
fixture_decode_test!(decode_block_7_appl_call, "block_7.msgpack", 7);
fixture_decode_test!(decode_block_8_keyreg, "block_8.msgpack", 8);
fixture_decode_test!(decode_block_9_pay, "block_9.msgpack", 9);

/// Verify that all blocks contain at least one transaction and the expected type.
#[test]
fn all_fixtures_have_expected_txn_types() {
    let fixtures: &[(&[u8], u64, &str)] = &[
        (include_bytes!("fixtures/block_1.msgpack"), 1, "pay"),
        (include_bytes!("fixtures/block_2.msgpack"), 2, "acfg"),
        (include_bytes!("fixtures/block_3.msgpack"), 3, "axfer"),
        (include_bytes!("fixtures/block_4.msgpack"), 4, "axfer"),
        (include_bytes!("fixtures/block_5.msgpack"), 5, "afrz"),
        (include_bytes!("fixtures/block_6.msgpack"), 6, "appl"),
        (include_bytes!("fixtures/block_7.msgpack"), 7, "appl"),
        (include_bytes!("fixtures/block_8.msgpack"), 8, "keyreg"),
        (include_bytes!("fixtures/block_9.msgpack"), 9, "pay"),
    ];

    for (bytes, round, expected_type) in fixtures {
        let br: BlockResponse = algo_codec::decode_block_response(bytes)
            .unwrap_or_else(|e| panic!("failed to decode block {round}: {e}"));
        assert!(
            !br.block.payset.is_empty(),
            "block {round} should have at least 1 txn"
        );
        assert_eq!(
            br.block.payset[0].txn.txn_type, *expected_type,
            "block {round} txn should be {expected_type}"
        );
    }
}
