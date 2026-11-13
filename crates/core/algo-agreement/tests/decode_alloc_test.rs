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

//! Certificate and proposal decoding must not allocate per map key or per
//! skipped field (issue #2317).
//!
//! go-algorand's msgp `UnmarshalMsg` compares key bytes in place and skips
//! unknown fields without building them. The decoders here used to read every
//! key as an owned `String` through `rmpv::decode::read_value` and to skip a
//! field by materialising it, which made certificate and proposal decoding
//! 2.8x and 2.9x slower than go.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::PathBuf;

use algo_agreement::codec::{decode_bundle, decode_compound_message};

struct CountingAlloc;

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: forwards every call unchanged to `System`; the counter is a
// thread-local `Cell` with a const initializer, so it never allocates.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Allocations (and reallocations) made by `f` on this thread.
fn allocations<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let before = ALLOCS.with(Cell::get);
    let out = f();
    (ALLOCS.with(Cell::get) - before, out)
}

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../benchmarks/fixtures/micro")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn decoding_a_certificate_does_not_allocate_per_key() {
    let data = fixture("cert-20.msgpack");
    let _ = decode_bundle(&data).expect("decode cert");
    let (n, bundle) = allocations(|| decode_bundle(&data).expect("decode cert"));
    let votes = (bundle.votes.len() + bundle.equivocation_votes.len()) as u64;
    assert!(votes >= 20, "the fixture holds a real certificate");
    // The vote vectors themselves, nothing per vote and nothing per key. A
    // key-allocating decoder needs more than ten allocations per vote.
    assert!(
        n <= 4,
        "decode_bundle made {n} allocations for {votes} votes, want at most 4"
    );
}

#[test]
fn decoding_a_proposal_does_not_allocate_for_the_second_pass() {
    let data = fixture("proposal.msgpack");
    let _ = decode_compound_message(&data).expect("decode proposal");
    let (block_only, _) =
        allocations(|| algo_types::Block::decode_from_bytes(&data).expect("decode block"));
    let (n, _) = allocations(|| decode_compound_message(&data).expect("decode proposal"));
    // Everything beyond the block decode is the scan for `oper` / `oprop` /
    // `sdpf` / `pv`: it reads fixed-size fields and skips the block's own.
    assert!(
        n <= block_only + 2,
        "decode_compound_message made {n} allocations, the block decode alone {block_only}"
    );
}
