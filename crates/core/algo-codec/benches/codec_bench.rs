use criterion::{black_box, criterion_group, criterion_main, Criterion};

use algo_codec::{
    compute_block_digest, compute_txn_id, decode_block, decode_block_response, encode_block,
};

/// Load a block-response fixture (msgpack bytes captured from go-algorand).
fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Benchmark: decode a BlockResponse from raw msgpack
// ---------------------------------------------------------------------------
fn bench_decode_block_response(c: &mut Criterion) {
    let bytes = fixture_bytes("block_1.msgpack");

    c.bench_function("decode_block_response (block 1, pay)", |b| {
        b.iter(|| {
            let _ = decode_block_response(black_box(&bytes)).unwrap();
        });
    });

    // Also bench a more complex fixture (appl-create) if available
    let bytes_appl = fixture_bytes("block_6.msgpack");
    c.bench_function("decode_block_response (block 6, appl)", |b| {
        b.iter(|| {
            let _ = decode_block_response(black_box(&bytes_appl)).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: decode a Block (without the BlockResponse wrapper)
// ---------------------------------------------------------------------------
fn bench_decode_block(c: &mut Criterion) {
    // First decode the response to get the block, re-encode it as a standalone block
    let response_bytes = fixture_bytes("block_1.msgpack");
    let br = decode_block_response(&response_bytes).unwrap();
    let block_bytes = encode_block(&br.block).unwrap();

    c.bench_function("decode_block (block 1, pay)", |b| {
        b.iter(|| {
            let _ = decode_block(black_box(&block_bytes)).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: encode a Block to msgpack
// ---------------------------------------------------------------------------
fn bench_encode_block(c: &mut Criterion) {
    let response_bytes = fixture_bytes("block_1.msgpack");
    let br = decode_block_response(&response_bytes).unwrap();
    let block = br.block;

    c.bench_function("encode_block (block 1, pay)", |b| {
        b.iter(|| {
            let _ = encode_block(black_box(&block)).unwrap();
        });
    });

    let response_bytes_appl = fixture_bytes("block_6.msgpack");
    let br_appl = decode_block_response(&response_bytes_appl).unwrap();
    let block_appl = br_appl.block;

    c.bench_function("encode_block (block 6, appl)", |b| {
        b.iter(|| {
            let _ = encode_block(black_box(&block_appl)).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: round-trip (decode then re-encode)
// ---------------------------------------------------------------------------
fn bench_round_trip(c: &mut Criterion) {
    let response_bytes = fixture_bytes("block_1.msgpack");
    let br = decode_block_response(&response_bytes).unwrap();
    let block_bytes = encode_block(&br.block).unwrap();

    c.bench_function("round_trip decode+encode (block 1)", |b| {
        b.iter(|| {
            let block = decode_block(black_box(&block_bytes)).unwrap();
            let _ = encode_block(black_box(&block)).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: compute_block_digest (canonical encode + SHA-512/256)
// ---------------------------------------------------------------------------
fn bench_block_digest(c: &mut Criterion) {
    let response_bytes = fixture_bytes("block_1.msgpack");
    let br = decode_block_response(&response_bytes).unwrap();
    let block = br.block;

    c.bench_function("compute_block_digest (block 1)", |b| {
        b.iter(|| {
            let _ = compute_block_digest(black_box(&block));
        });
    });

    let response_bytes_appl = fixture_bytes("block_6.msgpack");
    let br_appl = decode_block_response(&response_bytes_appl).unwrap();
    let block_appl = br_appl.block;

    c.bench_function("compute_block_digest (block 6, appl)", |b| {
        b.iter(|| {
            let _ = compute_block_digest(black_box(&block_appl));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: compute_txn_id (canonical encode txn + SHA-512/256)
// ---------------------------------------------------------------------------
fn bench_txn_id(c: &mut Criterion) {
    let response_bytes = fixture_bytes("block_1.msgpack");
    let br = decode_block_response(&response_bytes).unwrap();
    let txn = &br.block.payset[0].txn;

    c.bench_function("compute_txn_id (pay)", |b| {
        b.iter(|| {
            let _ = compute_txn_id(black_box(txn));
        });
    });

    let response_bytes_appl = fixture_bytes("block_6.msgpack");
    let br_appl = decode_block_response(&response_bytes_appl).unwrap();
    let txn_appl = &br_appl.block.payset[0].txn;

    c.bench_function("compute_txn_id (appl)", |b| {
        b.iter(|| {
            let _ = compute_txn_id(black_box(txn_appl));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark: extract_raw_payset_blobs
// ---------------------------------------------------------------------------
fn bench_extract_raw_payset(c: &mut Criterion) {
    let response_bytes = fixture_bytes("block_1.msgpack");

    c.bench_function("extract_raw_payset_blobs (block 1)", |b| {
        b.iter(|| {
            let _ = algo_codec::extract_raw_payset_blobs(black_box(&response_bytes)).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_decode_block_response,
    bench_decode_block,
    bench_encode_block,
    bench_round_trip,
    bench_block_digest,
    bench_txn_id,
    bench_extract_raw_payset,
);
criterion_main!(benches);
