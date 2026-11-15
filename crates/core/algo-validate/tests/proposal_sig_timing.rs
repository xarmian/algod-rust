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

//! Issue #2344: cold-cache validation time of a proposal of N signed payments
//! (`cargo test --release -p algo-validate --test proposal_sig_timing --
//! --ignored --nocapture`). Not a pass/fail test: it prints the time of a
//! cold pass and of a pass over a warm `VerifiedTransactionCache`.

use std::time::Instant;

use algo_types::{Address, Block, Round, SignedTransaction, Transaction};
use algo_validate::block::validate_block_with_cache;
use algo_validate::VerifiedTransactionCache;
use ed25519_dalek::{Signer, SigningKey};

const GH: [u8; 32] = [0xAA; 32];

fn signed(key: &SigningKey, i: u64) -> SignedTransaction {
    let txn = Transaction {
        txn_type: "pay".into(),
        sender: Address(key.verifying_key().to_bytes()),
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(1000),
        amount: 1 + i,
        receiver: Address([2u8; 32]),
        genesis_id: "test-v1".into(),
        genesis_hash: GH,
        ..Default::default()
    };
    let canonical = algo_codec::canonical_encode_transaction(&txn);
    let mut msg = b"TX".to_vec();
    msg.extend_from_slice(&canonical);
    let sig = key.sign(&msg);
    let mut stripped = txn;
    stripped.genesis_id = String::new();
    stripped.genesis_hash = [0u8; 32];
    SignedTransaction {
        txn: stripped,
        sig: sig.to_bytes(),
        has_genesis_id: true,
        ..Default::default()
    }
}

#[test]
#[ignore = "timing measurement, run with --ignored --nocapture"]
fn proposal_validation_time() {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    for n in [1_000u64, 10_000] {
        let mut block = Block {
            round: Round(1),
            timestamp: 100,
            genesis_id: "test-v1".into(),
            genesis_hash: GH,
            current_protocol: "future".into(),
            ..Default::default()
        };
        block.payset = (0..n).map(|i| signed(&key, i)).collect();
        let bytes: usize = block
            .payset
            .iter()
            .map(|s| algo_codec::canonical_encode_signed_txn_in_block(s).len())
            .sum();
        let max = algo_validate::rules::max_txn_bytes_per_block(&block.current_protocol).unwrap();
        block.load = algo_validate::rules::compute_expected_load(bytes, max);

        let cache = VerifiedTransactionCache::new((n as usize) * 2);
        let t = Instant::now();
        let cold = validate_block_with_cache(&block, Some(90), "test-v1", &GH, None, Some(&cache));
        let cold_ms = t.elapsed().as_secs_f64() * 1e3;
        assert!(cold.is_valid, "{:?}", cold.errors.first());
        let t = Instant::now();
        let warm = validate_block_with_cache(&block, Some(90), "test-v1", &GH, None, Some(&cache));
        let warm_ms = t.elapsed().as_secs_f64() * 1e3;
        assert!(warm.is_valid);
        println!("PROPOSAL n={n} cold={cold_ms:.1} ms warm_cache={warm_ms:.1} ms");
    }
}
