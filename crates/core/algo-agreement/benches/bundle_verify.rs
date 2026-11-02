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

//! Certificate-authentication micro benchmark (issue #2145, epic #2101):
//! `UnauthenticatedBundle::verify` on a real-vote CERT bundle of the size a
//! testnet certificate has (~25 votes), against the original strictly
//! sequential implementation. `RAYON_NUM_THREADS=1` shows the cost without
//! parallelism. Run with `cargo bench -p algo-agreement --bench bundle_verify`.

use criterion::{criterion_group, criterion_main, Criterion};

use algo_agreement::CERT;

#[path = "../tests/support/bundle_fixture.rs"]
mod fixture;
use fixture::{bundle, ledger, pool, proposal};

fn bundle_verify(c: &mut Criterion) {
    let voters = pool(25);
    let l = ledger(&voters);
    let b = bundle(&voters, CERT, proposal(0x11));
    // The benchmark is only meaningful if the bundle authenticates.
    let verified = b.verify(&l).expect("benchmark bundle must verify");
    assert_eq!(verified.votes.len(), 25);

    let mut g = c.benchmark_group("bundle_verify_25_votes");
    g.sample_size(20);
    g.bench_function("sequential_reference", |bch| {
        bch.iter(|| b.verify_reference_sequential(&l).expect("verifies"))
    });
    g.bench_function("parallel", |bch| {
        bch.iter(|| b.verify(&l).expect("verifies"))
    });
    g.finish();
}

criterion_group!(benches, bundle_verify);
criterion_main!(benches);
