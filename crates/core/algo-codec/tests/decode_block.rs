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
