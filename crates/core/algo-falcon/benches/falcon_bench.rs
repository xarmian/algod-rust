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

//! Falcon-1024 `det1024` backend comparison (Phase 21 stage 12, #1938):
//! keygen / sign / verify / CT conversion for every compiled backend
//! (`rust`, and `c` with the default `c-backend` feature), on the same
//! inputs. Run with `cargo bench -p algo-falcon`; results land in
//! `target/criterion/falcon/`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use algo_falcon::{
    falcon_convert_compressed_to_ct_with, falcon_keygen_with, falcon_sign_with, falcon_verify_with,
    FalconBackend, FALCON_SEED_SIZE,
};

fn bench_falcon(c: &mut Criterion) {
    let seed = [0x5au8; FALCON_SEED_SIZE];
    let msg32: Vec<u8> = (0..32u8).collect();
    let msg1000: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();

    let mut group = c.benchmark_group("falcon");
    group.sample_size(60);
    group.measurement_time(std::time::Duration::from_secs(8));
    for &b in FalconBackend::all() {
        let (pk, sk) = falcon_keygen_with(b, &seed).unwrap();
        let sig32 = falcon_sign_with(b, &sk, &msg32).unwrap();
        let sig1000 = falcon_sign_with(b, &sk, &msg1000).unwrap();

        group.bench_with_input(BenchmarkId::new("keygen", b), &b, |bn, &b| {
            bn.iter(|| falcon_keygen_with(b, black_box(&seed)).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("sign/32B", b), &b, |bn, &b| {
            bn.iter(|| falcon_sign_with(b, black_box(&sk), black_box(&msg32)).unwrap())
        });
        group.throughput(Throughput::Bytes(msg1000.len() as u64));
        group.bench_with_input(BenchmarkId::new("sign/1000B", b), &b, |bn, &b| {
            bn.iter(|| falcon_sign_with(b, black_box(&sk), black_box(&msg1000)).unwrap())
        });
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("verify/32B", b), &b, |bn, &b| {
            bn.iter(|| {
                falcon_verify_with(b, black_box(&pk), black_box(&sig32), black_box(&msg32)).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("verify/1000B", b), &b, |bn, &b| {
            bn.iter(|| {
                falcon_verify_with(b, black_box(&pk), black_box(&sig1000), black_box(&msg1000))
                    .unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("convert_to_ct", b), &b, |bn, &b| {
            bn.iter(|| falcon_convert_compressed_to_ct_with(b, black_box(&sig32)).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_falcon);
criterion_main!(benches);
