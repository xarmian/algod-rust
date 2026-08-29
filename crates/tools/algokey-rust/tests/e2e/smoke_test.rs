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

//! E2E smoke test for the TASK-184 harness.
//!
//! Validates the full minimum-viable path:
//!   bring up localnet → discover funded faucet → build/sign/submit a
//!   zero-algo self-pay → wait for confirmation → assert on-chain.
//!
//! Gated by `--features e2e`. Run with:
//!   ```
//!   make localnet-up && cargo test -p algokey-rust --features e2e --test e2e_smoke
//!   ```
//!
//! The harness is idempotent — if a localnet is already up, it reuses
//! it and leaves it running on Drop. If not, it brings one up and tears
//! it down at end of test.

#[path = "mod.rs"]
mod e2e;

use algo_codec::canonical_encode_signed_transaction;
use algo_types::{Round, Transaction, TxnType};
use e2e::accounts::sign;

#[tokio::test]
async fn smoke_self_pay_round_trips() {
    let net = e2e::Localnet::bring_up().await.expect("bring up localnet");
    let faucet = e2e::discover_faucet(&net).await.expect("discover faucet");

    assert!(
        faucet.balance > 0,
        "faucet must have a positive balance (got {})",
        faucet.balance,
    );
    assert_eq!(
        faucet.mnemonic.split_whitespace().count(),
        25,
        "mnemonic must be exactly 25 words",
    );

    // Build a self-pay for 0 microAlgos with the suggested params.
    let params = net
        .client()
        .suggested_transaction_params()
        .await
        .expect("suggested params");

    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender: faucet.address,
        fee: params.fee.max(params.min_fee),
        first_valid: Round(params.last_round),
        last_valid: Round(params.last_round + 1000),
        genesis_hash: params.genesis_hash.0,
        genesis_id: params.genesis_id.clone(),
        receiver: faucet.address,
        amount: 0,
        ..Transaction::default()
    };

    let signed = sign(txn, &faucet.signing_key());
    let encoded = canonical_encode_signed_transaction(&signed);

    let txid = e2e::submit_raw_txn(&net, &encoded)
        .await
        .expect("submit self-pay");

    // Devnet block intervals are sub-second; 10 rounds is generous.
    let confirmed = e2e::wait_for_confirmation(&net, &txid, 10)
        .await
        .expect("self-pay should land in a block");

    assert!(
        confirmed.confirmed_round >= params.last_round,
        "confirmed round {} must be ≥ suggested last_round {}",
        confirmed.confirmed_round,
        params.last_round,
    );

    // Faucet account is genesis-online, so this also exercises status fetch.
    let status = e2e::get_account_status(&net, faucet.address)
        .await
        .expect("get_account_status");
    assert!(
        status.is_online(),
        "genesis faucet should be Online, got {:?}",
        status.status,
    );
    assert!(
        status.amount > 0,
        "faucet balance must be positive after self-pay (got {})",
        status.amount,
    );
}
