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

use algo_types::AccountData;

// Protocol parameters for minimum balance computation and fixed limits.
//
// Values from go-algorand consensus parameters (v4.6.0).
//
// The majority of consensus parameters are now sourced from
// `algo_types::ConsensusParams`, which is the single source of truth
// and is threaded through AVM and ledger execution contexts.
//
// The constants below are kept for:
//   - `min_balance()`: used by state.rs and sqlite.rs where ConsensusParams
//     is not yet threaded (TODO: thread ConsensusParams through min_balance).
//   - `MAX_APP_CALL_DEPTH`: a fixed protocol constant not in ConsensusParams
//     (go-algorand `maxAppCallDepth = 8`).
//   - Schema constants: used by state.rs for Merkle trie computation.

pub const MIN_BALANCE: u64 = 100_000;
pub const ASSET_OPT_IN_MIN_BALANCE: u64 = 100_000;
pub const APP_FLAT_PARAMS_MIN_BALANCE: u64 = 100_000;
pub const APP_FLAT_OPT_IN_MIN_BALANCE: u64 = 100_000;
// Three-tier schema costing from go-algorand:
// Total per uint = SCHEMA_MIN_BALANCE_PER_ENTRY + SCHEMA_UINT_MIN_BALANCE = 28,500
// Total per byte-slice = SCHEMA_MIN_BALANCE_PER_ENTRY + SCHEMA_BYTES_MIN_BALANCE = 50,000
pub const SCHEMA_MIN_BALANCE_PER_ENTRY: u64 = 25_000;
pub const SCHEMA_UINT_MIN_BALANCE: u64 = 3_500;
pub const SCHEMA_BYTES_MIN_BALANCE: u64 = 25_000;
pub const BOX_FLAT_MIN_BALANCE: u64 = 2_500;
pub const BOX_BYTE_MIN_BALANCE: u64 = 400;

/// Maximum inner app-call depth (go-algorand `maxAppCallDepth = 8`).
/// A value of 0 prevents inner app calls; 8 means top-level + 8 levels deep.
/// This is a fixed protocol constant, not in ConsensusParams.
pub const MAX_APP_CALL_DEPTH: usize = 8;

// ── Test-only constants ────────────────────────────────────────────
// The following are used only in test code. Production code reads these
// values from `ConsensusParams`.

/// Maximum inner transactions per app call (test reference only).
#[cfg(test)]
pub const MAX_INNER_TRANSACTIONS: usize = 16;

/// Minimum transaction fee in microAlgos (test reference only).
#[cfg(test)]
pub const MIN_TXN_FEE: u64 = 1000;

/// Compute minimum balance for an account based on its opted-in assets,
/// created assets, created apps, opted-in apps, extra app pages, boxes,
/// and aggregate app schema.
///
/// Schema cost matches Go's three-tier formula:
///   SCHEMA_MIN_BALANCE_PER_ENTRY * (num_uint + num_byte_slice)
///   + SCHEMA_UINT_MIN_BALANCE * num_uint
///   + SCHEMA_BYTES_MIN_BALANCE * num_byte_slice
///
/// TODO: Accept `ConsensusParams` to make this version-aware.
pub fn min_balance(account: &AccountData) -> u64 {
    // NOTE: total_assets_opted_in already includes creator holdings (incremented
    // on asset create), matching Go's single `TotalAssets` counter. Do NOT add
    // total_created_assets separately — that would double-count.
    let schema = &account.total_app_schema;
    let num_entries = schema.num_uint + schema.num_byte_slice;
    let schema_cost = SCHEMA_MIN_BALANCE_PER_ENTRY * num_entries
        + SCHEMA_UINT_MIN_BALANCE * schema.num_uint
        + SCHEMA_BYTES_MIN_BALANCE * schema.num_byte_slice;

    MIN_BALANCE
        + account.total_assets_opted_in * ASSET_OPT_IN_MIN_BALANCE
        + account.total_created_apps * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_apps_opted_in * APP_FLAT_OPT_IN_MIN_BALANCE
        + account.total_extra_app_pages as u64 * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_boxes * BOX_FLAT_MIN_BALANCE
        + account.total_box_bytes * BOX_BYTE_MIN_BALANCE
        + schema_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_balance_default_account() {
        let account = AccountData::default();
        assert_eq!(min_balance(&account), MIN_BALANCE);
    }

    #[test]
    fn test_min_balance_with_assets() {
        let account = AccountData {
            total_assets_opted_in: 3,
            ..Default::default()
        };
        assert_eq!(min_balance(&account), 100_000 + 3 * 100_000);
    }

    #[test]
    fn test_min_balance_with_apps_and_boxes() {
        let account = AccountData {
            total_created_apps: 1,
            total_apps_opted_in: 2,
            total_extra_app_pages: 1,
            total_boxes: 5,
            total_box_bytes: 1000,
            ..Default::default()
        };
        // 100k + 1*100k + 2*100k + 1*100k + 5*2500 + 1000*400
        assert_eq!(
            min_balance(&account),
            100_000 + 100_000 + 200_000 + 100_000 + 12_500 + 400_000
        );
    }
}
