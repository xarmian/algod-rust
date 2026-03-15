use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use algo_codec::{
    compute_block_digest, compute_txn_id, decode_block, decode_block_fast, decode_block_response,
    decode_block_response_fast, encode_block,
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
// A/B Comparison: decode BlockResponse (serde vs fast path)
// ---------------------------------------------------------------------------
fn bench_decode_block_response_ab(c: &mut Criterion) {
    let fixtures: &[(&str, &str)] = &[
        ("block_1.msgpack", "block 1 (pay)"),
        ("block_6.msgpack", "block 6 (appl)"),
        ("block_8.msgpack", "block 8 (keyreg)"),
    ];

    let mut group = c.benchmark_group("decode_block_response");
    for &(file, label) in fixtures {
        let bytes = fixture_bytes(file);

        group.bench_with_input(BenchmarkId::new("serde", label), &bytes, |b, data| {
            b.iter(|| {
                let _ = decode_block_response(black_box(data)).unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("fast", label), &bytes, |b, data| {
            b.iter(|| {
                let _ = decode_block_response_fast(black_box(data)).unwrap();
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// A/B Comparison: decode Block (serde vs fast path)
// ---------------------------------------------------------------------------
fn bench_decode_block_ab(c: &mut Criterion) {
    let fixtures: &[(&str, &str)] = &[
        ("block_1.msgpack", "block 1 (pay)"),
        ("block_6.msgpack", "block 6 (appl)"),
        ("block_8.msgpack", "block 8 (keyreg)"),
    ];

    let mut group = c.benchmark_group("decode_block");
    for &(file, label) in fixtures {
        // Decode the response with serde to get a standalone block, then re-encode it
        let response_bytes = fixture_bytes(file);
        let br = decode_block_response(&response_bytes).unwrap();
        let block_bytes = encode_block(&br.block).unwrap();

        group.bench_with_input(BenchmarkId::new("serde", label), &block_bytes, |b, data| {
            b.iter(|| {
                let _ = decode_block(black_box(data)).unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("fast", label), &block_bytes, |b, data| {
            b.iter(|| {
                let _ = decode_block_fast(black_box(data)).unwrap();
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: encode a Block to msgpack (unchanged — no fast path yet)
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

// ---------------------------------------------------------------------------
// A/B Comparison: full pipeline decode all fixtures (serde vs fast)
// ---------------------------------------------------------------------------
fn bench_decode_all_fixtures(c: &mut Criterion) {
    let fixtures: &[(&str, &str)] = &[
        ("block_1.msgpack", "pay"),
        ("block_2.msgpack", "acfg"),
        ("block_3.msgpack", "axfer"),
        ("block_4.msgpack", "axfer-clawback"),
        ("block_5.msgpack", "afrz"),
        ("block_6.msgpack", "appl-create"),
        ("block_7.msgpack", "appl-call"),
        ("block_8.msgpack", "keyreg"),
        ("block_9.msgpack", "pay-2"),
    ];

    // Pre-load all fixture bytes
    let all_bytes: Vec<(&str, Vec<u8>)> = fixtures
        .iter()
        .map(|&(file, label)| (label, fixture_bytes(file)))
        .collect();

    let mut group = c.benchmark_group("decode_all_responses");

    group.bench_function("serde", |b| {
        b.iter(|| {
            for (_, data) in &all_bytes {
                let _ = decode_block_response(black_box(data)).unwrap();
            }
        });
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            for (_, data) in &all_bytes {
                let _ = decode_block_response_fast(black_box(data)).unwrap();
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decode_block_response_ab,
    bench_decode_block_ab,
    bench_encode_block,
    bench_round_trip,
    bench_block_digest,
    bench_txn_id,
    bench_extract_raw_payset,
    bench_decode_all_fixtures,
);
criterion_main!(benches);
