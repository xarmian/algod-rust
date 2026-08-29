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

//! Byte-for-byte conformance of canonical block JSON vs go-algorand.
//!
//! Golden files under `fixtures/block_json/<name>.json` were produced by
//! decoding `<name>.msgpack` (a raw `{block, cert}` block response) and
//! re-encoding the block via go-algorand v4.6.0-stable's
//! `protocol.JSONStrictHandle` — exactly what `GET /v2/blocks/{round}?format=json`
//! emits. The Rust `encode_block_json` must reproduce those bytes exactly.

use algo_rest_api::block_json::encode_block_json;

fn check(name: &str, msgpack: &[u8], golden: &str) {
    let got = encode_block_json(msgpack).unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
    let got = String::from_utf8(got).expect("utf8");
    assert_eq!(
        got, golden,
        "{name}: canonical block JSON must match go-algorand byte-for-byte"
    );
}

macro_rules! golden_test {
    ($test:ident, $name:literal) => {
        #[test]
        fn $test() {
            let msgpack = include_bytes!(concat!("fixtures/block_json/", $name, ".msgpack"));
            let golden = include_str!(concat!("fixtures/block_json/", $name, ".json"));
            check($name, msgpack, golden);
        }
    };
}

golden_test!(block_json_pay_block1, "block1");
golden_test!(block_json_pay_block_1, "block_1");
golden_test!(block_json_acfg_block_2, "block_2");
golden_test!(block_json_axfer_block_3, "block_3");
golden_test!(block_json_afrz_block_5, "block_5");
golden_test!(block_json_pay_block_9, "block_9");
// App-call block with a rich eval-delta: global/local deltas, logs (incl. a
// binary log exercising invalid-UTF-8 escaping), app args/accounts, and a
// nested inner transaction with addresses.
golden_test!(block_json_appl_eval_delta, "synthetic_appl");
