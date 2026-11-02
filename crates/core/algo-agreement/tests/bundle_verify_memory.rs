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

//! Issue #2145 review: peak heap use of verifying a large bundle must stay
//! close to the sequential reference's (no per-vote copies of the consensus
//! parameters held for the whole bundle). Own test binary: it installs a
//! counting global allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use algo_agreement::CERT;

#[path = "support/bundle_fixture.rs"]
mod fixture;
use fixture::*;

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = CURRENT.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        CURRENT.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Peak bytes allocated above the starting level while running `f`.
fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst) - base)
}

#[test]
fn large_bundle_peak_heap_stays_close_to_the_sequential_reference() {
    let voters = pool(100);
    let l = ledger(&voters);
    let b = bundle(&voters, CERT, proposal(0x11));
    // warm up (creates the verifier pool, lazy statics)
    let _ = b.verify(&l);

    let (r_new, new_peak) = peak_of(|| b.verify(&l));
    let (r_ref, ref_peak) = peak_of(|| b.verify_reference_sequential(&l));
    assert_eq!(format!("{r_new:?}"), format!("{r_ref:?}"));
    eprintln!("peak heap, 100 votes: verify {new_peak} B, reference {ref_peak} B");
    // The pool's per-thread work (<= 16 in flight) is a few KiB each; the
    // old per-vote parameter copies held for the whole bundle were not.
    assert!(
        new_peak <= 2 * ref_peak + 256 * 1024,
        "peak {new_peak} B vs reference {ref_peak} B"
    );
}
