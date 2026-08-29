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

use algo_codec::decode_block_response;
use algo_validate::{
    validate_genesis_consistency, validate_lease_constraints, validate_transaction_group,
    validate_transaction_rules,
};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/algo-codec/tests/fixtures")
}

/// Load a block fixture and decode it.
/// Returns None if the fixture file doesn't exist.
fn load_block(round: u64) -> Option<algo_types::BlockResponse> {
    let path = fixture_dir().join(format!("block_{round}.msgpack"));
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Some(decode_block_response(&bytes).unwrap_or_else(|e| panic!("decode block {round}: {e}")))
}

/// Skip a test if fixtures are not available, printing a message.
macro_rules! require_fixture {
    ($expr:expr, $msg:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                eprintln!("SKIPPED: {} (run `make fixtures` to generate)", $msg);
                return;
            }
        }
    };
}

/// Restore genesis_id and genesis_hash on transactions that had them stripped
/// for block storage. In Algorand blocks, genesis_id is stripped when hgi=true,
/// and genesis_hash is ALWAYS stripped (it's redundant with the block header)
/// regardless of the hgh flag value.
fn restore_genesis_fields(br: &algo_types::BlockResponse) -> Vec<algo_types::SignedTransaction> {
    br.block
        .payset
        .iter()
        .map(|stx| {
            let mut full = stx.clone();
            if stx.has_genesis_id && full.txn.genesis_id.is_empty() {
                full.txn.genesis_id.clone_from(&br.block.genesis_id);
            }
            // Genesis hash is always stripped from block-stored transactions
            if full.txn.genesis_hash == [0u8; 32] {
                full.txn.genesis_hash = br.block.genesis_hash;
            }
            full
        })
        .collect()
}

/// Validate transaction rules for a single block fixture.
macro_rules! rules_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );

            if br.block.payset.is_empty() {
                eprintln!("block {} has no transactions, skipping", $round);
                return;
            }

            let txns = restore_genesis_fields(&br);

            // Validate individual transaction rules.
            for (i, stx) in txns.iter().enumerate() {
                validate_transaction_rules(&stx.txn, false).unwrap_or_else(|e| {
                    panic!(
                        "transaction rules failed for block {} txn {}: {e}",
                        $round, i
                    )
                });
            }

            // Validate transaction groups.
            validate_transaction_group(&txns)
                .unwrap_or_else(|e| panic!("group validation failed for block {}: {e}", $round));

            // Validate lease constraints.
            validate_lease_constraints(&txns)
                .unwrap_or_else(|e| panic!("lease validation failed for block {}: {e}", $round));

            // Validate genesis consistency.
            validate_genesis_consistency(&txns, &br.block.genesis_id, &br.block.genesis_hash)
                .unwrap_or_else(|e| panic!("genesis consistency failed for block {}: {e}", $round));
        }
    };
}

rules_test!(rules_block_1_pay, 1);
rules_test!(rules_block_2_acfg, 2);
rules_test!(rules_block_3_axfer_optin, 3);
rules_test!(rules_block_4_axfer_transfer, 4);
rules_test!(rules_block_5_afrz, 5);
rules_test!(rules_block_6_appl_create, 6);
rules_test!(rules_block_7_appl_call, 7);
rules_test!(rules_block_8_keyreg, 8);
rules_test!(rules_block_9_pay_tail, 9);

/// Validate all blocks in a single sweep.
#[test]
fn rules_validate_all_blocks() {
    let mut validated = 0;
    for round in 1..=9 {
        let br = match load_block(round) {
            Some(br) => br,
            None => continue,
        };

        let txns = restore_genesis_fields(&br);
        for (i, stx) in txns.iter().enumerate() {
            validate_transaction_rules(&stx.txn, false).unwrap_or_else(|e| {
                panic!("transaction rules failed for block {round} txn {i}: {e}")
            });
        }

        validate_transaction_group(&txns)
            .unwrap_or_else(|e| panic!("group validation failed for block {round}: {e}"));

        validate_lease_constraints(&txns)
            .unwrap_or_else(|e| panic!("lease validation failed for block {round}: {e}"));

        validate_genesis_consistency(&txns, &br.block.genesis_id, &br.block.genesis_hash)
            .unwrap_or_else(|e| panic!("genesis consistency failed for block {round}: {e}"));

        validated += txns.len();
    }

    if validated == 0 {
        eprintln!("SKIPPED: no block fixtures found (run `make fixtures` to generate)");
    } else {
        eprintln!("validated {validated} transactions across all block fixtures (rules, groups, leases, genesis)");
    }
}
