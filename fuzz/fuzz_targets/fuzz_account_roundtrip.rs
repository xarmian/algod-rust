// Copyright (c) 2026 Algod DAO
// SPDX-License-Identifier: MIT
// See the LICENSE-MIT file in the repository root for the full license text.

#![no_main]

use libfuzzer_sys::fuzz_target;

use algo_types::SignedTransaction;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize arbitrary bytes as a SignedTransaction via msgpack.
    let stx: SignedTransaction = match rmp_serde::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Re-serialize — should not panic regardless of field contents.
    let encoded = match rmp_serde::to_vec_named(&stx) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Verify roundtrip: decode the re-encoded bytes.
    // This may differ from the original input (msgpack normalization),
    // but decoding our own output must not panic.
    let _stx2: SignedTransaction = match rmp_serde::from_slice(&encoded) {
        Ok(v) => v,
        Err(_) => return,
    };
});
