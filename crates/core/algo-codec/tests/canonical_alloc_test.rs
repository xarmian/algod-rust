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

//! The canonical encoder must not allocate per field (issue #2314).
//!
//! go-algorand's msgp-generated `MarshalMsg` appends every field of a struct
//! to one buffer. `CanonicalMap` used to encode every non-zero field into its
//! own `Vec<u8>`, which made transaction encoding, txid and the block
//! commitments 1.6x to 2x slower than go. These tests pin the allocation
//! budget and the exact bytes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use algo_codec::{canonical_encode_signed_transaction, canonical_encode_transaction};
use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};

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

fn payment() -> Transaction {
    Transaction {
        txn_type: TxnType::Pay,
        sender: Address([0x11; 32]),
        receiver: Address([0x22; 32]),
        amount: 1_000_000,
        fee: 1000,
        first_valid: Round(70_000),
        last_valid: Round(71_000),
        genesis_id: "testnet-v1.0".to_string(),
        genesis_hash: [0x33; 32],
        note: vec![0xAB; 40].into(),
        lease: [0x44; 32],
        ..Transaction::default()
    }
}

/// `{sig, txn}` built from the transaction's own canonical bytes.
fn signed(tx: &Transaction) -> SignedTransaction {
    let mut b = vec![0x82, 0xa3, b's', b'i', b'g', 0xc4, 64];
    b.extend_from_slice(&[0x55; 64]);
    b.extend_from_slice(&[0xa3, b't', b'x', b'n']);
    b.extend_from_slice(&canonical_encode_transaction(tx));
    SignedTransaction::decode_from_bytes(&b).expect("decode the signed payment")
}

const PAYMENT_HEX: &str = "8ba3616d74ce000f4240a3666565cd03e8a26676ce00011170a367656eac746573746e65742d76312e30a26768c4203333333333333333333333333333333333333333333333333333333333333333a26c76ce00011558a26c78c4204444444444444444444444444444444444444444444444444444444444444444a46e6f7465c428ababababababababababababababababababababababababababababababababababababababababa3726376c4202222222222222222222222222222222222222222222222222222222222222222a3736e64c4201111111111111111111111111111111111111111111111111111111111111111a474797065a3706179";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_payment_encodes_to_the_pinned_bytes() {
    assert_eq!(hex(&canonical_encode_transaction(&payment())), PAYMENT_HEX);
}

#[test]
fn encoding_a_transaction_does_not_allocate_per_field() {
    let tx = payment();
    // Warm up anything lazily initialised.
    let _ = canonical_encode_transaction(&tx);
    let (n, bytes) = allocations(|| canonical_encode_transaction(&tx));
    assert_eq!(hex(&bytes), PAYMENT_HEX);
    // 11 fields: a per-field encoder needs at least 11 allocations.
    assert!(
        n <= 4,
        "canonical_encode_transaction made {n} allocations for an 11-field payment, want at most 4"
    );
}

#[test]
fn encoding_a_signed_transaction_does_not_allocate_per_field() {
    let stx = signed(&payment());
    let _ = canonical_encode_signed_transaction(&stx);
    let (n, bytes) = allocations(|| canonical_encode_signed_transaction(&stx));
    assert!(hex(&bytes).ends_with(PAYMENT_HEX), "txn is the last field");
    assert!(
        n <= 8,
        "canonical_encode_signed_transaction made {n} allocations, want at most 8"
    );
}

#[test]
fn keys_added_out_of_order_are_still_sorted() {
    // `SignedTransaction` adds "sig" before "sgnr"; the output must be sorted.
    let mut stx = signed(&payment());
    stx.auth_addr = Some(Address([0x66; 32]));
    let bytes = canonical_encode_signed_transaction(&stx);
    let sgnr = bytes.windows(4).position(|w| w == b"sgnr").expect("sgnr");
    let sig = bytes.windows(4).position(|w| w == b"\xa3sig").expect("sig");
    assert!(sgnr < sig, "sgnr must sort before sig");
    let back = SignedTransaction::decode_from_bytes(&bytes).expect("round trip");
    assert_eq!(back, stx);
}
