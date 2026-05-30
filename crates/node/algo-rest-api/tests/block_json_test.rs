//! Byte-for-byte conformance of canonical block JSON vs go-algorand.
//!
//! Golden files under `fixtures/block_json/<name>.json` were produced by
//! decoding `<name>.msgpack` (a raw `{block, cert}` block response) and
//! re-encoding the block via go-algorand v4.5.1-stable's
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
