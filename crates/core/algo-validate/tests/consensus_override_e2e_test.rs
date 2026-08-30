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

//! Issue #762's centerpiece acceptance criterion: a real transaction, run
//! through `algo_validate::validate_block` -- the actual block-validation
//! entry point real algod-rust nodes call, not a unit test on the lookup
//! function in isolation -- must have an overridden consensus parameter
//! (`MinTxnFee`) enforced once that override is installed via
//! [`algo_types::consensus::install_consensus_overrides`].
//!
//! `validate_block` resolves its `ConsensusParams` via
//! `algo_types::consensus::consensus_params_for_version(&block.current_protocol)`
//! (see `crates/core/algo-validate/src/block.rs`) -- the exact choke point
//! issue #762 threads the override registry through. This test proves the
//! thread-through end-to-end: the same transaction/fee that validates
//! cleanly under the pristine built-in table must be rejected once an
//! override raises the minimum fee, with no changes to `validate_block`
//! itself.
//!
//! Its own integration-test file/process (like the `algo-types` override
//! tests): `install_consensus_overrides` writes a process-global `OnceLock`
//! at most once, so this must not share a process with any test assuming
//! pristine (no-override) behavior.

use algo_types::consensus::{
    built_in_consensus_protocols, install_consensus_overrides, CONSENSUS_FUTURE,
};
use algo_types::{Address, Round, SignedTransaction, Transaction};
use ed25519_dalek::{Signer, SigningKey};

fn genesis_hash() -> [u8; 32] {
    [0xAA; 32]
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A minimal valid block carrying a single signed payment transaction paying
/// exactly `fee`.
fn block_with_payment(fee: u64) -> algo_types::Block {
    let key = signing_key();
    let pk = key.verifying_key();
    let sender = Address(pk.to_bytes());

    let txn = Transaction {
        txn_type: "pay".into(),
        sender,
        fee,
        first_valid: Round(1),
        last_valid: Round(1000),
        amount: 0,
        receiver: Address([2u8; 32]),
        genesis_id: "test-v1".into(),
        genesis_hash: genesis_hash(),
        ..Default::default()
    };

    let canonical = algo_codec::canonical_encode_transaction(&txn);
    let mut msg = Vec::with_capacity(2 + canonical.len());
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical);
    let sig = key.sign(&msg);

    let mut stripped_txn = txn;
    stripped_txn.genesis_id = String::new();
    stripped_txn.genesis_hash = [0u8; 32];

    let stx = SignedTransaction {
        txn: stripped_txn,
        sig: sig.to_bytes(),
        msig: None,
        lsig: None,
        pqsig: None,
        auth_addr: None,
        has_genesis_id: true,
        has_genesis_hash: true,
        closing_amount: 0,
        asset_closing_amount: 0,
        sender_rewards: 0,
        receiver_rewards: 0,
        close_rewards: 0,
        eval_delta: None,
        apply_data_config_asset: 0,
        apply_data_application_id: 0,
    };

    algo_types::Block {
        round: Round(1),
        branch: [0u8; 32],
        seed: [0u8; 32],
        txn_commitment: [0u8; 32],
        timestamp: 100,
        genesis_id: "test-v1".into(),
        genesis_hash: genesis_hash(),
        proposer: Address::default(),
        fee_sink: Address::default(),
        rewards_pool: Address::default(),
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: CONSENSUS_FUTURE.into(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: [0u8; 64],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        load: 0,
        congestion_tax: 0,
        payset: vec![stx],
    }
}

fn has_fee_error(errors: &[algo_validate::BlockValidationError]) -> bool {
    errors.iter().any(|e| {
        matches!(e, algo_validate::BlockValidationError::TransactionValidationFailed { error, .. }
            if error.contains("below minimum"))
    })
}

#[test]
fn overridden_min_txn_fee_is_enforced_by_the_real_validate_block_path() {
    // ── Baseline: under the pristine built-in table, a transaction paying
    // exactly the built-in minimum fee validates cleanly through the real
    // `validate_block` entry point.
    let pristine_min_fee = built_in_consensus_protocols()
        .get(CONSENSUS_FUTURE)
        .expect("\"future\" is a known built-in version")
        .min_txn_fee;

    let before = block_with_payment(pristine_min_fee);
    let result_before =
        algo_validate::validate_block(&before, Some(90), "test-v1", &genesis_hash(), None);
    assert!(
        !has_fee_error(&result_before.errors),
        "paying the built-in minimum fee must not be a fee error pre-override, got: {:?}",
        result_before.errors
    );

    // ── Install an override that raises "future"'s MinTxnFee well above
    // what the transaction above pays, exactly like bin/algod-rust's startup
    // would from a real consensus.json (the override map shape here is
    // literally `preload_configurable_consensus_protocols`'s return type).
    let mut merged = built_in_consensus_protocols();
    let mut future_params = merged.get(CONSENSUS_FUTURE).unwrap().clone();
    future_params.min_txn_fee = pristine_min_fee.saturating_mul(5).max(pristine_min_fee + 1);
    let overridden_min_fee = future_params.min_txn_fee;
    merged.insert(CONSENSUS_FUTURE.to_string(), future_params);
    install_consensus_overrides(&merged);

    // ── The exact same fee that passed a moment ago must now be rejected by
    // the exact same `validate_block` call, with no code change to
    // `validate_block` itself -- proof the override threads all the way
    // through `consensus_params_for_version` into the real validation path.
    let after = block_with_payment(pristine_min_fee);
    let result_after =
        algo_validate::validate_block(&after, Some(90), "test-v1", &genesis_hash(), None);
    assert!(
        has_fee_error(&result_after.errors),
        "paying only the old (pre-override) minimum fee must now fail the fee check \
         under the overridden MinTxnFee={overridden_min_fee}, got: {:?}",
        result_after.errors
    );

    // ── Paying the new, overridden minimum fee validates cleanly again.
    let paid_enough = block_with_payment(overridden_min_fee);
    let result_paid_enough =
        algo_validate::validate_block(&paid_enough, Some(90), "test-v1", &genesis_hash(), None);
    assert!(
        !has_fee_error(&result_paid_enough.errors),
        "paying the new overridden minimum fee must validate cleanly, got: {:?}",
        result_paid_enough.errors
    );
}
