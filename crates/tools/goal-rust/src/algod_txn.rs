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

//! The algod requests of the commands that send a transaction, as go's goal
//! makes them (issue #2489): `libgoal.Client.SuggestedParams`,
//! `BroadcastTransaction` / `BroadcastTransactionGroup` (`POST
//! /v2/transactions`), `Status`, `WaitForRound` and
//! `PendingTransactionInformation` through go's REST client
//! ([`crate::algod_rest`]), and goal's `waitForCommit`
//! (`cmd/goal/clerk.go`). Every error is go's text.

use algo_rest_client::{AlgodClient, SuggestedParams};

use crate::algod_rest::{self, Endpoint};
use crate::go_codec_json;

/// go: `errorRequestFail`.
const ERROR_REQUEST_FAIL: &str = "Error processing command: ";

fn endpoint(algod: &AlgodClient) -> Endpoint {
    (algod.base_url().to_string(), algod.token().to_string())
}

/// go's `client.SuggestedParams()`.
pub fn suggested_params(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
) -> Result<SuggestedParams, String> {
    let v = algod_rest::get_json(
        rt,
        &endpoint(algod),
        "/v2/transactions/params",
        &[],
        &go_codec_json::TRANSACTION_PARAMETERS,
    )?;
    let text = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let num = |k: &str| v[k].as_u64().unwrap_or(0);
    // go copies the `[]byte` into the txn's `[32]byte` (`copy`)
    let mut genesis_hash = [0u8; 32];
    if let Some(b64) = v["genesis-hash"].as_str() {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap_or_default();
        let n = raw.len().min(32);
        genesis_hash[..n].copy_from_slice(&raw[..n]);
    }
    Ok(SuggestedParams {
        consensus_version: text("consensus-version"),
        fee: num("fee"),
        genesis_hash: algo_types::Digest(genesis_hash),
        genesis_id: text("genesis-id"),
        last_round: num("last-round"),
        min_fee: num("min-fee"),
    })
}

/// go's `client.BroadcastTransaction(stx)` / `BroadcastTransactionGroup`:
/// `POST /v2/transactions` of the encoded signed transactions, the txid
/// algod answers.
pub fn broadcast(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    signed: &[u8],
) -> Result<String, String> {
    broadcast_with_params(rt, algod, signed, false)
}

/// go's `SendRawTransactionGroupWithParams(txgroup, skipPqAddressCheck)`:
/// `?skip-pq-address-check=true` only when set (`rawTransactionQueryParams`).
pub fn broadcast_with_params(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    signed: &[u8],
    skip_pq_address_check: bool,
) -> Result<String, String> {
    let query: &[(&str, &str)] = if skip_pq_address_check {
        &[("skip-pq-address-check", "true")]
    } else {
        &[]
    };
    let v = algod_rest::post_json(
        rt,
        &endpoint(algod),
        "/v2/transactions",
        query,
        Some(signed),
        &go_codec_json::POST_TRANSACTIONS,
    )?;
    Ok(v["txId"].as_str().unwrap_or("").to_string())
}

/// go's `client.Status()`: the last round.
pub fn status_last_round(rt: &tokio::runtime::Runtime, algod: &AlgodClient) -> Result<u64, String> {
    let v = algod_rest::get_json(
        rt,
        &endpoint(algod),
        "/v2/status",
        &[],
        &go_codec_json::NODE_STATUS,
    )?;
    Ok(v["last-round"].as_u64().unwrap_or(0))
}

/// go's `client.WaitForRound(round)` (`RestClient.WaitForRound(round,
/// time.Minute)`): `/v2/status` every 200 ms until its last round reaches
/// `round`.
pub fn wait_for_round(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    round: u64,
) -> Result<u64, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let last = status_last_round(rt, algod)?;
        if last >= round {
            return Ok(last);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timeout waiting for round {round} with last round = {last}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// go's `client.PendingTransactionInformation(txid)`, decoded as a
/// `model.PendingTransactionResponse`.
pub fn pending_transaction_information(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    txid: &str,
) -> Result<serde_json::Value, String> {
    algod_rest::get_json(
        rt,
        &endpoint(algod),
        &format!("/v2/transactions/pending/{txid}"),
        &[],
        &go_codec_json::PENDING_TRANSACTION,
    )
}

/// The confirmed round of a pending transaction (go's `ConfirmedRound`).
pub fn confirmed_round(txn: &serde_json::Value) -> u64 {
    txn["confirmed-round"].as_u64().unwrap_or(0)
}

/// go's `waitForCommit(client, txid, lastValid)` (`cmd/goal/clerk.go`): it
/// prints `Transaction <txid> committed in round <r>` (or `... still pending
/// as of round <r>` for each round it waits) and returns the pending
/// transaction, or go's error text.
pub fn wait_for_commit(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    txid: &str,
    last_valid: u64,
) -> Result<serde_json::Value, String> {
    let fail = |e: String| format!("{ERROR_REQUEST_FAIL}{e}");
    let mut last_round = status_last_round(rt, algod).map_err(fail)?;
    loop {
        let txn = pending_transaction_information(rt, algod, txid).map_err(fail)?;
        let confirmed = confirmed_round(&txn);
        if confirmed > 0 {
            report_info(&format!(
                "Transaction {txid} committed in round {confirmed}"
            ));
            return Ok(txn);
        }
        let pool_error = txn["pool-error"].as_str().unwrap_or("");
        if !pool_error.is_empty() {
            return Err(format!(
                "Transaction {txid} kicked out of local node pool: {pool_error}"
            ));
        }
        if last_valid > 0 && last_round >= last_valid {
            return Err(format!(
                "Transaction {txid} expired before it could be included in a block"
            ));
        }
        report_info(&format!(
            "Transaction {txid} still pending as of round {last_round}"
        ));
        last_round = wait_for_round(rt, algod, last_round + 1).map_err(fail)?;
    }
}

/// The fields of a decoded `model.PendingTransactionResponse` the commands
/// read after the commit.
pub fn pending_info(txn: &serde_json::Value) -> algo_rest_client::PendingTxnInfo {
    use base64::Engine as _;
    let logs = txn["logs"].as_array().map(|ls| {
        ls.iter()
            .map(|l| {
                base64::engine::general_purpose::STANDARD
                    .decode(l.as_str().unwrap_or(""))
                    .unwrap_or_default()
            })
            .collect()
    });
    algo_rest_client::PendingTxnInfo {
        confirmed_round: txn["confirmed-round"].as_u64(),
        pool_error: txn["pool-error"].as_str().unwrap_or("").to_string(),
        logs,
        application_index: txn["application-index"].as_u64(),
        asset_index: txn["asset-index"].as_u64(),
    }
}

/// [`wait_for_commit`], the committed transaction as a
/// [`algo_rest_client::PendingTxnInfo`].
pub fn wait_for_commit_info(
    rt: &tokio::runtime::Runtime,
    algod: &AlgodClient,
    txid: &str,
    last_valid: u64,
) -> Result<algo_rest_client::PendingTxnInfo, String> {
    wait_for_commit(rt, algod, txid, last_valid).map(|t| pending_info(&t))
}

/// go's `reportInfof`: the text on stdout.
fn report_info(msg: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(crate::formatting::report_info_text(msg).as_bytes());
    let _ = out.flush();
}
