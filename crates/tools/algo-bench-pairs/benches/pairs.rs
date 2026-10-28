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

//! Criterion half of the paired Go/Rust micro-benchmarks (issue #2103).
//!
//! One benchmark per pair id, named exactly like the id (criterion group =
//! the part before the first `/`), so `cargo bench -p algo-bench-pairs
//! --bench pairs -- codec/` selects a family and the results land in
//! `target/criterion/<group>/<name>/new/{sample,estimates}.json`, which
//! `scripts/bench/micro_convert.py` turns into bench-compare results.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_pairs(c: &mut Criterion) {
    let dir = algo_bench_pairs::fixture_dir();
    for id in algo_bench_pairs::IDS {
        let (group, name) = id.split_once('/').expect("pair ids are <group>/<name>");
        // Built lazily: criterion only calls the routine for benchmarks its
        // filter selects, so a filtered run loads only those fixtures.
        let mut case: Option<algo_bench_pairs::Case> = None;
        let mut g = c.benchmark_group(group);
        g.bench_function(name, |b| {
            let case = case.get_or_insert_with(|| {
                let mut c = algo_bench_pairs::build(&dir, id).unwrap_or_else(|e| panic!("{e}"));
                c.bench_iteration(); // fail fast before timing
                c
            });
            // Reset (stateful pairs only) + operation, as on the Go side.
            b.iter(|| case.bench_iteration());
        });
        g.finish();
    }
}

criterion_group!(benches, bench_pairs);
criterion_main!(benches);
