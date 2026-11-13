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

//! The payset commitments must not clone every transaction (issue #2318).
//!
//! go-algorand hashes each payset entry from its encoding. The commitments
//! here used to deep-clone every `Transaction` just to restore its genesis
//! fields before hashing it (`GenesisRestoreRule::restored_txn`), which
//! together with the per-field encoder made them about 2x slower than go.
//!
//! One test only: the allocation counter is process-wide (the leaf hashing
//! may run on worker threads), so nothing else may run in this binary.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use algo_validate::merkle::{
    compute_payset_merkle_root, compute_payset_merkle_root_raw, compute_vector_commitment,
    compute_vector_commitment_raw, HashAlgo,
};

struct CountingAlloc;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards every call unchanged to `System`; the counter is a static
// atomic, so counting never allocates.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Allocations (and reallocations) made by the whole process during `f`.
fn allocations<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let before = ALLOCS.load(Ordering::Relaxed);
    let out = f();
    (ALLOCS.load(Ordering::Relaxed) - before, out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn commitments_do_not_clone_the_transactions() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../benchmarks/fixtures/micro/block-large.msgpack");
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let block = algo_codec::decode_block(&data).expect("decode block-large");
    let n = block.payset.len() as u64;
    assert!(n >= 500, "the fixture is a large block ({n} transactions)");

    // Warm up (thread pool start-up, lazily initialised tables).
    let _ = compute_payset_merkle_root(&block);
    let _ = compute_vector_commitment(&block, HashAlgo::Sha256);

    let (merkle_allocs, root) = allocations(|| compute_payset_merkle_root(&block));
    let (vc_allocs, vc) = allocations(|| compute_vector_commitment(&block, HashAlgo::Sha256));
    let (_, vc512) = allocations(|| compute_vector_commitment(&block, HashAlgo::Sha512));

    // The roots, pinned (go generates this fixture; `cargo test -p
    // algo-bench-pairs` compares the first two with go's output).
    assert_eq!(hex(&root), MERKLE_ROOT);
    assert_eq!(hex(&vc), VC_SHA256_ROOT);
    assert_eq!(hex(&vc512), VC_SHA512_ROOT);

    // Measured before the change: 11.0 allocations per transaction for the
    // Merkle root (a clone of the transaction, two encodings into fresh
    // buffers, the transaction encoded a third time inside the
    // SignedTxnInBlock) and 18.0 for the vector commitment. Now: the field
    // index and arena of each of the three maps, nothing for the output
    // (reused scratch buffers) and nothing for the clone.
    assert!(
        merkle_allocs <= 7 * n,
        "compute_payset_merkle_root made {merkle_allocs} allocations for {n} transactions \
         ({:.1} per transaction), want at most 7",
        merkle_allocs as f64 / n as f64
    );
    assert!(
        vc_allocs <= 11 * n,
        "compute_vector_commitment made {vc_allocs} allocations for {n} transactions \
         ({:.1} per transaction), want at most 11",
        vc_allocs as f64 / n as f64
    );

    // The raw-blob variants take the same (chunked, parallel) leaf path with
    // the stored SignedTxnInBlock bytes: fed the canonical encodings they
    // must give the same roots, entry for entry in payset order.
    let raw: Vec<Vec<u8>> = block
        .payset
        .iter()
        .map(algo_codec::canonical_encode_signed_txn_in_block)
        .collect();
    assert_eq!(
        hex(&compute_payset_merkle_root_raw(&block, &raw)),
        MERKLE_ROOT
    );
    assert_eq!(
        hex(&compute_vector_commitment_raw(
            &block,
            HashAlgo::Sha256,
            &raw
        )),
        VC_SHA256_ROOT
    );
    // Swapping two entries of the raw blobs changes the root: the chunk
    // offset really selects each transaction's own blob.
    let mut swapped = raw.clone();
    let last = swapped.len() - 1;
    swapped.swap(300, last);
    assert_ne!(
        hex(&compute_payset_merkle_root_raw(&block, &swapped)),
        MERKLE_ROOT
    );
}

const MERKLE_ROOT: &str = "b98c32555439ba63a3d804d2ebe73cbe809dc1272ac8fb4b49b915977c6f5aec";
const VC_SHA256_ROOT: &str = "64552554c8571d1a630c6c5d9ca3654e9790b0631f99b06ac85459ad2091ae8e";
const VC_SHA512_ROOT: &str =
    "c3c4a55df477047e251af702c739d6cc4e818380ad6b9716a08e3db009ff1af0ad33dbf5b2603cbf839a427fbb03ba4f7b1753965c0d2f2de813339e2718cd5e";
