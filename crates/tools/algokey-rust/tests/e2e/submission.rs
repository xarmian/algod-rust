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

//! Submission + confirmation polling + account-status helpers (TASK-184).
//!
//! Thin wrappers over `AlgodClient` that surface the patterns the e2e
//! tests need most:
//!
//! - `submit_raw_txn` — POST `/v2/transactions`
//! - `wait_for_confirmation` — poll `/v2/transactions/pending/{txid}`
//!   until the txn lands in a block or the round window elapses
//! - `get_account_status` — fetch `/v2/accounts/{addr}` and surface
//!   participation fields (status, voting keys, validity window)
//!   that TASK-185's headline keyreg assertions need

use std::time::Duration;

use algo_error::{AlgoError, Result};
use algo_rest_client::{BlockSource, TxId};
use algo_types::Address;
use serde::Deserialize;

use super::localnet::Localnet;

/// Poll interval when waiting for a transaction to be committed. Chosen so
/// the smoke test finishes within ~3-4 dev-mode block intervals.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Submit a raw msgpack-encoded `SignedTransaction` (or transaction group)
/// to the localnet.
pub async fn submit_raw_txn(net: &Localnet, encoded: &[u8]) -> Result<TxId> {
    net.client().send_raw_transaction(encoded).await
}

/// Confirmation outcome from [`wait_for_confirmation`].
#[derive(Debug, Clone)]
pub struct ConfirmedTxn {
    pub txid: TxId,
    pub confirmed_round: u64,
}

/// Poll algod until `txid` is committed to a block, or until `max_rounds`
/// rounds elapse from the current last-committed round.
///
/// Returns `AlgoError::Network` if:
/// - `max_rounds` elapses without confirmation
/// - the pool rejects the txn (non-empty `pool-error`)
pub async fn wait_for_confirmation(
    net: &Localnet,
    txid: &TxId,
    max_rounds: u64,
) -> Result<ConfirmedTxn> {
    let start_round = net.client().get_status().await?.last_round;
    let deadline_round = start_round.saturating_add(max_rounds);

    loop {
        let info = net.client().get_pending_transaction(txid).await?;
        if info.is_rejected() {
            return Err(AlgoError::Network {
                message: format!("txn {txid} rejected by pool: {}", info.pool_error),
            });
        }
        if let Some(round) = info.confirmed_round {
            return Ok(ConfirmedTxn {
                txid: txid.clone(),
                confirmed_round: round,
            });
        }

        let current = net.client().get_status().await?.last_round;
        if current > deadline_round {
            return Err(AlgoError::Network {
                message: format!(
                    "txn {txid} not confirmed within {max_rounds} rounds (started at {start_round}, now {current})"
                ),
            });
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Participation fields surfaced by `/v2/accounts/{addr}` when the account
/// has registered voting keys. These mirror the algod OpenAPI shape (see
/// `../go-algorand/daemon/algod/api/server/v2/handlers.go` —
/// `AccountParticipation`).
#[derive(Debug, Clone, Deserialize)]
pub struct ParticipationFields {
    /// Ed25519 voting participation public key.
    #[serde(rename = "vote-participation-key", with = "bytes_base64")]
    pub vote_participation_key: [u8; 32],

    /// VRF selection participation public key.
    #[serde(rename = "selection-participation-key", with = "bytes_base64")]
    pub selection_participation_key: [u8; 32],

    /// State-proof commitment (Merkle root) — present in v32+ keyregs.
    #[serde(rename = "state-proof-key", default, with = "opt_bytes_base64")]
    pub state_proof_key: Option<Vec<u8>>,

    /// First valid round for this participation key.
    #[serde(rename = "vote-first-valid")]
    pub vote_first_valid: u64,

    /// Last valid round for this participation key.
    #[serde(rename = "vote-last-valid")]
    pub vote_last_valid: u64,

    /// Key dilution.
    #[serde(rename = "vote-key-dilution")]
    pub vote_key_dilution: u64,
}

/// Participation status + balance + (optional) voting key block for an
/// account. Used to assert that an algokey-rust-generated partkey landed
/// correctly via keyreg.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountStatus {
    /// `"Online"`, `"Offline"`, or `"Not Participating"`.
    pub status: String,
    /// Balance in microAlgos.
    pub amount: u64,
    /// Voting keys, when the account is registered as a participating node.
    #[serde(default)]
    pub participation: Option<ParticipationFields>,
}

impl AccountStatus {
    pub fn is_online(&self) -> bool {
        self.status == "Online"
    }
    pub fn is_offline(&self) -> bool {
        self.status == "Offline"
    }
}

/// Fetch the account's current status from `/v2/accounts/{addr}` and
/// deserialize only the fields tests need. This bypasses
/// [`algo_rest_client::AccountInfo`] to avoid coupling TASK-184 to a
/// schema change in `algo-rest-client`; if other consumers grow a need
/// for participation fields we can promote this type later.
pub async fn get_account_status(net: &Localnet, addr: Address) -> Result<AccountStatus> {
    let url = format!(
        "{}/v2/accounts/{}",
        net.rest_url(),
        addr.to_algorand_string()
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .header("X-Algo-API-Token", net.rest_token())
        .send()
        .await
        .map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!("GET {url}"),
        })?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| AlgoError::RestClient {
        source: Box::new(e),
        context: format!("reading body for {url}"),
    })?;

    if !status.is_success() {
        return Err(AlgoError::Network {
            message: format!("GET {url} → {status}: {body}"),
        });
    }

    serde_json::from_str::<AccountStatus>(&body).map_err(|e| AlgoError::RestClient {
        source: Box::new(e),
        context: format!("parsing AccountStatus from {url}: body={body}"),
    })
}

/// Adapter: `vote-participation-key` and `selection-participation-key` are
/// JSON-encoded as standard-base64 strings on the wire; we decode straight
/// to fixed 32-byte arrays so callers don't deal with the encoding.
mod bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let bytes = STANDARD.decode(raw.as_bytes()).map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom(format!(
                "expected 32-byte voting key, got {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Adapter for the optional `state-proof-key` field: algod omits it for
/// accounts whose keyreg didn't include a state-proof commitment.
mod opt_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let raw = Option::<String>::deserialize(d)?;
        match raw {
            None => Ok(None),
            Some(s) => Ok(Some(
                STANDARD.decode(s.as_bytes()).map_err(D::Error::custom)?,
            )),
        }
    }
}
