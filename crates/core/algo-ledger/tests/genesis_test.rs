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

//! Integration tests for genesis.json loading.
//!
//! Tests the parser against the real mainnet genesis.json fixture,
//! verifying well-known addresses, allocation counts, and account properties.

use std::path::PathBuf;

use algo_ledger::LedgerState;
use algo_types::{AccountStatus, Address};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load_mainnet_genesis() -> LedgerState {
    let path = fixture_dir().join("mainnet-genesis.json");
    assert!(path.exists(), "mainnet-genesis.json fixture missing");
    LedgerState::from_genesis(&path).expect("failed to load mainnet genesis.json")
}

// ── Well-known addresses ─────────────────────────────────────

const FEE_SINK: &str = "Y76M3MSY6DKBRHBL7C3NNDXGS5IIMQVQVUAB6MP4XEMMGVF2QWNPL226CA";
const REWARDS_POOL: &str = "737777777777777777777777777777777777777777777777777UFEJ2CI";

#[test]
fn test_mainnet_fee_sink_address() {
    let state = load_mainnet_genesis();
    let expected = Address::from_algorand_string(FEE_SINK).unwrap();
    assert_eq!(state.fee_sink, expected, "fee sink address mismatch");
}

#[test]
fn test_mainnet_rewards_pool_address() {
    let state = load_mainnet_genesis();
    let expected = Address::from_algorand_string(REWARDS_POOL).unwrap();
    assert_eq!(
        state.rewards_pool, expected,
        "rewards pool address mismatch"
    );
}

// ── Genesis metadata ─────────────────────────────────────────

#[test]
fn test_mainnet_genesis_id() {
    let state = load_mainnet_genesis();
    assert_eq!(state.genesis_id, "mainnet-v1.0");
}

#[test]
fn test_mainnet_protocol_version_set() {
    let state = load_mainnet_genesis();
    assert!(!state.protocol.is_empty(), "protocol version should be set");
    assert!(
        state.protocol.contains("algorandfoundation/specs"),
        "protocol should reference algorand specs"
    );
}

// ── Allocation counts ────────────────────────────────────────

#[test]
fn test_mainnet_total_allocations() {
    let state = load_mainnet_genesis();
    // Mainnet genesis has 102 allocations (all unique addresses).
    assert_eq!(state.accounts.len(), 102);
}

#[test]
fn test_mainnet_online_accounts_count() {
    let state = load_mainnet_genesis();
    let online_count = state
        .accounts
        .values()
        .filter(|a| a.status == AccountStatus::Online)
        .count();
    // Mainnet genesis has 30 online (participating) accounts.
    assert_eq!(online_count, 30);
}

#[test]
fn test_mainnet_not_participating_accounts_count() {
    let state = load_mainnet_genesis();
    let not_participating_count = state
        .accounts
        .values()
        .filter(|a| a.status == AccountStatus::NotParticipating)
        .count();
    // Mainnet genesis has 72 not-participating accounts.
    assert_eq!(not_participating_count, 72);
}

// ── Specific account balances ────────────────────────────────

#[test]
fn test_mainnet_fee_sink_balance() {
    let state = load_mainnet_genesis();
    let addr = Address::from_algorand_string(FEE_SINK).unwrap();
    let account = state.get_account(&addr).expect("fee sink account missing");
    assert_eq!(account.micro_algos, 1_000_000);
    assert_eq!(account.status, AccountStatus::NotParticipating);
}

#[test]
fn test_mainnet_rewards_pool_balance() {
    let state = load_mainnet_genesis();
    let addr = Address::from_algorand_string(REWARDS_POOL).unwrap();
    let account = state
        .get_account(&addr)
        .expect("rewards pool account missing");
    // Rewards pool gets 10,000,000 ALGO (10_000_000_000_000 microAlgos)
    assert_eq!(account.micro_algos, 10_000_000_000_000);
    assert_eq!(account.status, AccountStatus::NotParticipating);
}

#[test]
fn test_mainnet_large_offline_account_balance() {
    let state = load_mainnet_genesis();
    // N5BGWISAJSYT7MVW2BDTTEHOXFQF4QQH4VKSMKJEOA4PHPYND43D6WWTIU has 1,740,000 ALGO
    let addr =
        Address::from_algorand_string("N5BGWISAJSYT7MVW2BDTTEHOXFQF4QQH4VKSMKJEOA4PHPYND43D6WWTIU")
            .unwrap();
    let account = state.get_account(&addr).expect("large account missing");
    assert_eq!(account.micro_algos, 1_740_000_000_000_000);
    assert_eq!(account.status, AccountStatus::NotParticipating);
}

// ── Online accounts have participation keys ──────────────────

#[test]
fn test_mainnet_online_accounts_have_participation_keys() {
    let state = load_mainnet_genesis();
    for (addr, account) in &state.accounts {
        if account.status == AccountStatus::Online {
            assert!(
                account.vote_id.is_some(),
                "online account {} missing vote key",
                addr
            );
            assert!(
                account.selection_id.is_some(),
                "online account {} missing selection key",
                addr
            );
            assert!(
                account.vote_last_valid > 0,
                "online account {} has zero vote_last_valid",
                addr
            );
            assert!(
                account.vote_key_dilution > 0,
                "online account {} has zero vote_key_dilution",
                addr
            );
        }
    }
}

#[test]
fn test_mainnet_offline_accounts_have_no_participation_keys() {
    let state = load_mainnet_genesis();
    for (addr, account) in &state.accounts {
        if account.status == AccountStatus::NotParticipating
            || account.status == AccountStatus::Offline
        {
            assert!(
                account.vote_id.is_none(),
                "offline/not-participating account {} should not have vote key",
                addr
            );
            assert!(
                account.selection_id.is_none(),
                "offline/not-participating account {} should not have selection key",
                addr
            );
        }
    }
}

// ── Specific online account verification ─────────────────────

#[test]
fn test_mainnet_specific_online_account() {
    let state = load_mainnet_genesis();
    // GVCPSWDNSL54426YL76DZFVIZI5OIDC7WEYSJLBFFEQYPXM7LTGSDGC4SA
    // has 49,998,988 ALGO and is online
    let addr =
        Address::from_algorand_string("GVCPSWDNSL54426YL76DZFVIZI5OIDC7WEYSJLBFFEQYPXM7LTGSDGC4SA")
            .unwrap();
    let account = state.get_account(&addr).expect("online account missing");
    assert_eq!(account.micro_algos, 49_998_988_000_000);
    assert_eq!(account.status, AccountStatus::Online);
    assert!(account.vote_id.is_some());
    assert!(account.selection_id.is_some());
    assert_eq!(account.vote_last_valid, 3_000_000);
    assert_eq!(account.vote_key_dilution, 10_000);
}
