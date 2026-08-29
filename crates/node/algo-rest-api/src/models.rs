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

//! REST API response model structs that match go-algorand's JSON API format.
//!
//! These structs mirror the types in go-algorand's
//! `daemon/algod/api/server/v2/generated/model/types.go`.
//!
//! Conversion functions from internal types (e.g. `AccountData`) are not
//! included here -- they will be added in a later wave.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TealValue / TealKeyValue
// ---------------------------------------------------------------------------

/// Represents a TEAL value.
///
/// Matches go-algorand's `model.TealValue`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiTealValue {
    /// \[tb\] bytes value.
    pub bytes: String,

    /// \[tt\] value type. Value `1` refers to **bytes**, value `2` refers to **uint**.
    #[serde(rename = "type")]
    pub value_type: u64,

    /// \[ui\] uint value.
    pub uint: u64,
}

/// Represents a key-value pair in an application store.
///
/// Matches go-algorand's `model.TealKeyValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTealKeyValue {
    pub key: String,

    /// Represents a TEAL value.
    pub value: ApiTealValue,
}

/// A key-value store for use in an application.
///
/// Matches go-algorand's `TealKeyValueStore = []TealKeyValue`.
pub type TealKeyValueStore = Vec<ApiTealKeyValue>;

// ---------------------------------------------------------------------------
// ApplicationStateSchema
// ---------------------------------------------------------------------------

/// Specifies maximums on the number of each type that may be stored.
///
/// Matches go-algorand's `model.ApplicationStateSchema`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiApplicationStateSchema {
    /// \[nbs\] num of byte slices.
    #[serde(rename = "num-byte-slice")]
    pub num_byte_slice: u64,

    /// \[nui\] num of uints.
    #[serde(rename = "num-uint")]
    pub num_uint: u64,
}

// ---------------------------------------------------------------------------
// AssetHolding
// ---------------------------------------------------------------------------

/// Describes an asset held by an account.
///
/// Matches go-algorand's `model.AssetHolding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAssetHolding {
    /// \[a\] number of units held.
    pub amount: u64,

    /// Asset ID of the holding.
    #[serde(rename = "asset-id")]
    pub asset_id: u64,

    /// \[f\] whether or not the holding is frozen.
    #[serde(rename = "is-frozen")]
    pub is_frozen: bool,
}

// ---------------------------------------------------------------------------
// AssetParams
// ---------------------------------------------------------------------------

/// AssetParams specifies the parameters for an asset.
///
/// Matches go-algorand's `model.AssetParams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAssetParams {
    /// \[c\] Address of account used to clawback holdings of this asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clawback: Option<String>,

    /// The address that created this asset.
    pub creator: String,

    /// \[dc\] The number of digits to use after the decimal point when displaying
    /// this asset.
    pub decimals: u64,

    /// \[df\] Whether holdings of this asset are frozen by default.
    #[serde(rename = "default-frozen", skip_serializing_if = "Option::is_none")]
    pub default_frozen: Option<bool>,

    /// \[f\] Address of account used to freeze holdings of this asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freeze: Option<String>,

    /// \[m\] Address of account used to manage the keys of this asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,

    /// \[am\] A commitment to some unspecified asset metadata.
    #[serde(
        rename = "metadata-hash",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub metadata_hash: Option<Vec<u8>>,

    /// \[an\] Name of this asset, as supplied by the creator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Base64 encoded name of this asset, as supplied by the creator.
    #[serde(
        rename = "name-b64",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub name_b64: Option<Vec<u8>>,

    /// \[r\] Address of account holding reserve (non-minted) units of this asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserve: Option<String>,

    /// \[t\] The total number of units of this asset.
    pub total: u64,

    /// \[un\] Name of a unit of this asset, as supplied by the creator.
    #[serde(rename = "unit-name", skip_serializing_if = "Option::is_none")]
    pub unit_name: Option<String>,

    /// Base64 encoded name of a unit of this asset, as supplied by the creator.
    #[serde(
        rename = "unit-name-b64",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub unit_name_b64: Option<Vec<u8>>,

    /// \[au\] URL where more information about the asset can be retrieved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Base64 encoded URL where more information about the asset can be retrieved.
    #[serde(
        rename = "url-b64",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub url_b64: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Asset (wrapper)
// ---------------------------------------------------------------------------

/// Specifies both the unique identifier and the parameters for an asset.
///
/// Matches go-algorand's `model.Asset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAsset {
    /// Unique asset identifier.
    pub index: u64,

    /// AssetParams specifies the parameters for an asset.
    pub params: ApiAssetParams,
}

/// An entry in `AccountResponse.created_assets`.
///
/// A distinct, narrower type from [`ApiAsset`] (rather than making
/// `ApiAsset::params` itself optional): `ApiAsset` is also reused as
/// [`AssetResponse`] for `GET /v2/assets/{id}`, where params are always
/// required, not an optional output — making them `Option` there would force
/// every read site to handle a `None` that can never legitimately occur,
/// risking an unwrap-panic on a path that already handles untrusted input.
/// `params` is `None` only when the caller requested
/// `exclude=created-assets-params` (go-algorand v4.6.0-stable, issue #507)
/// — the asset index is still returned, but its params are omitted
/// (matches go's `*model.AssetParams` + omitempty on `model.Asset`, which
/// go-algorand reuses for both contexts since Go pointers dereference
/// cheaply where Rust's `Option` does not).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCreatedAsset {
    /// Unique asset identifier.
    pub index: u64,

    /// AssetParams specifies the parameters for an asset, omitted when
    /// `exclude=created-assets-params` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ApiAssetParams>,
}

// ---------------------------------------------------------------------------
// ApplicationParams
// ---------------------------------------------------------------------------

/// Stores the global information associated with an application.
///
/// Matches go-algorand's `model.ApplicationParams`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiApplicationParams {
    /// \[approv\] approval program.
    #[serde(rename = "approval-program", with = "base64_bytes")]
    pub approval_program: Vec<u8>,

    /// \[clearp\] clear state program.
    #[serde(rename = "clear-state-program", with = "base64_bytes")]
    pub clear_state_program: Vec<u8>,

    /// The address that created this application.
    pub creator: String,

    /// \[epp\] the amount of extra program pages available to this app.
    #[serde(
        rename = "extra-program-pages",
        skip_serializing_if = "Option::is_none"
    )]
    pub extra_program_pages: Option<u64>,

    /// Represents a key-value store for use in an application.
    #[serde(rename = "global-state", skip_serializing_if = "Option::is_none")]
    pub global_state: Option<TealKeyValueStore>,

    /// Specifies maximums on the number of each type that may be stored.
    #[serde(
        rename = "global-state-schema",
        skip_serializing_if = "Option::is_none"
    )]
    pub global_state_schema: Option<ApiApplicationStateSchema>,

    /// Specifies maximums on the number of each type that may be stored.
    #[serde(rename = "local-state-schema", skip_serializing_if = "Option::is_none")]
    pub local_state_schema: Option<ApiApplicationStateSchema>,

    /// \[ss\] the account responsible for extra pages and global state MBR.
    #[serde(rename = "size-sponsor", skip_serializing_if = "Option::is_none")]
    pub size_sponsor: Option<String>,

    /// \[v\] the number of updates to the application programs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

// ---------------------------------------------------------------------------
// Application (wrapper)
// ---------------------------------------------------------------------------

/// Application index and its parameters.
///
/// Matches go-algorand's `model.Application`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiApplication {
    /// \[appidx\] application index.
    pub id: u64,

    /// Stores the global information associated with an application.
    pub params: ApiApplicationParams,
}

/// An entry in `AccountResponse.created_apps`. See [`ApiCreatedAsset`] for
/// why this is a distinct type from [`ApiApplication`] rather than making
/// `ApiApplication::params` itself optional — the same reasoning applies
/// (`ApiApplication` is also reused as [`ApplicationResponse`] for
/// `GET /v2/applications/{id}`, where params are always required). `params`
/// is `None` only when the caller requested `exclude=created-apps-params` (go-algorand
/// v4.6.0-stable, issue #507).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCreatedApplication {
    /// \[appidx\] application index.
    pub id: u64,

    /// Stores the global information associated with an application,
    /// omitted when `exclude=created-apps-params` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ApiApplicationParams>,
}

// ---------------------------------------------------------------------------
// ApplicationLocalState
// ---------------------------------------------------------------------------

/// Stores local state associated with an application.
///
/// Matches go-algorand's `model.ApplicationLocalState`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiApplicationLocalState {
    /// The application which this local state is for.
    pub id: u64,

    /// Represents a key-value store for use in an application.
    #[serde(rename = "key-value", skip_serializing_if = "Option::is_none")]
    pub key_value: Option<TealKeyValueStore>,

    /// Specifies maximums on the number of each type that may be stored.
    pub schema: ApiApplicationStateSchema,
}

// ---------------------------------------------------------------------------
// AccountParticipation
// ---------------------------------------------------------------------------

/// AccountParticipation describes the parameters used by this account in
/// consensus protocol.
///
/// Matches go-algorand's `model.AccountParticipation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAccountParticipation {
    /// \[sel\] Selection public key (if any) currently registered for this round.
    #[serde(rename = "selection-participation-key", with = "base64_bytes")]
    pub selection_participation_key: Vec<u8>,

    /// \[stprf\] Root of the state proof key (if any).
    #[serde(
        rename = "state-proof-key",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub state_proof_key: Option<Vec<u8>>,

    /// \[voteFst\] First round for which this participation is valid.
    #[serde(rename = "vote-first-valid")]
    pub vote_first_valid: u64,

    /// \[voteKD\] Number of subkeys in each batch of participation keys.
    #[serde(rename = "vote-key-dilution")]
    pub vote_key_dilution: u64,

    /// \[voteLst\] Last round for which this participation is valid.
    #[serde(rename = "vote-last-valid")]
    pub vote_last_valid: u64,

    /// \[vote\] root participation public key (if any) currently registered for
    /// this round.
    #[serde(rename = "vote-participation-key", with = "base64_bytes")]
    pub vote_participation_key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AccountResponse (full Account model)
// ---------------------------------------------------------------------------

/// Account information at a given round.
///
/// Matches go-algorand's `model.Account`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    /// The account public key.
    pub address: String,

    /// \[algo\] total number of MicroAlgos in the account.
    pub amount: u64,

    /// Specifies the amount of MicroAlgos in the account, without the pending
    /// rewards.
    #[serde(rename = "amount-without-pending-rewards")]
    pub amount_without_pending_rewards: u64,

    /// \[appl\] applications local data stored in this account.
    #[serde(rename = "apps-local-state", skip_serializing_if = "Option::is_none")]
    pub apps_local_state: Option<Vec<ApiApplicationLocalState>>,

    /// \[teap\] the sum of all extra application program pages for this account.
    #[serde(
        rename = "apps-total-extra-pages",
        skip_serializing_if = "Option::is_none"
    )]
    pub apps_total_extra_pages: Option<u64>,

    /// Specifies maximums on the number of each type that may be stored.
    #[serde(rename = "apps-total-schema", skip_serializing_if = "Option::is_none")]
    pub apps_total_schema: Option<ApiApplicationStateSchema>,

    /// \[asset\] assets held by this account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<Vec<ApiAssetHolding>>,

    /// \[spend\] the address against which signing should be checked.
    #[serde(rename = "auth-addr", skip_serializing_if = "Option::is_none")]
    pub auth_addr: Option<String>,

    /// \[appp\] parameters of applications created by this account including app
    /// global data.
    #[serde(rename = "created-apps", skip_serializing_if = "Option::is_none")]
    pub created_apps: Option<Vec<ApiCreatedApplication>>,

    /// \[apar\] parameters of assets created by this account.
    #[serde(rename = "created-assets", skip_serializing_if = "Option::is_none")]
    pub created_assets: Option<Vec<ApiCreatedAsset>>,

    /// Whether or not the account can receive block incentives if its balance
    /// is in range at proposal time.
    #[serde(rename = "incentive-eligible", skip_serializing_if = "Option::is_none")]
    pub incentive_eligible: Option<bool>,

    /// The round in which this account last went online, or explicitly renewed
    /// their online status.
    #[serde(rename = "last-heartbeat", skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<u64>,

    /// The round in which this account last proposed the block.
    #[serde(rename = "last-proposed", skip_serializing_if = "Option::is_none")]
    pub last_proposed: Option<u64>,

    /// MicroAlgo balance required by the account.
    #[serde(rename = "min-balance")]
    pub min_balance: u64,

    /// AccountParticipation describes the parameters used by this account in
    /// consensus protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participation: Option<ApiAccountParticipation>,

    /// Amount of MicroAlgos of pending rewards in this account.
    #[serde(rename = "pending-rewards")]
    pub pending_rewards: u64,

    /// \[ebase\] used as part of the rewards computation. Only applicable to
    /// accounts which are participating.
    #[serde(rename = "reward-base", skip_serializing_if = "Option::is_none")]
    pub reward_base: Option<u64>,

    /// \[ern\] total rewards of MicroAlgos the account has received, including
    /// pending rewards.
    pub rewards: u64,

    /// The round for which this information is relevant.
    pub round: u64,

    /// Indicates what type of signature is used by this account.
    #[serde(rename = "sig-type", skip_serializing_if = "Option::is_none")]
    pub sig_type: Option<String>,

    /// \[onl\] delegation status of the account's MicroAlgos.
    pub status: String,

    /// The count of all applications that have been opted in.
    #[serde(rename = "total-apps-opted-in")]
    pub total_apps_opted_in: u64,

    /// The count of all assets that have been opted in.
    #[serde(rename = "total-assets-opted-in")]
    pub total_assets_opted_in: u64,

    /// \[tbxb\] The total number of bytes used by this account's app's box keys
    /// and values.
    #[serde(rename = "total-box-bytes", skip_serializing_if = "Option::is_none")]
    pub total_box_bytes: Option<u64>,

    /// \[tbx\] The number of existing boxes created by this account's app.
    #[serde(rename = "total-boxes", skip_serializing_if = "Option::is_none")]
    pub total_boxes: Option<u64>,

    /// The count of all apps (AppParams objects) created by this account.
    #[serde(rename = "total-created-apps")]
    pub total_created_apps: u64,

    /// The count of all assets (AssetParams objects) created by this account.
    #[serde(rename = "total-created-assets")]
    pub total_created_assets: u64,
}

// ---------------------------------------------------------------------------
// AccountAssetResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/accounts/{addr}/assets/{id}` endpoint.
///
/// Matches go-algorand's `model.AccountAssetResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAssetResponse {
    /// Describes an asset held by an account.
    #[serde(rename = "asset-holding", skip_serializing_if = "Option::is_none")]
    pub asset_holding: Option<ApiAssetHolding>,

    /// AssetParams specifies the parameters for an asset.
    #[serde(rename = "created-asset", skip_serializing_if = "Option::is_none")]
    pub created_asset: Option<ApiAssetParams>,

    /// The round for which this information is relevant.
    pub round: u64,
}

// ---------------------------------------------------------------------------
// AccountApplicationResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/accounts/{addr}/applications/{id}` endpoint.
///
/// Matches go-algorand's `model.AccountApplicationResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountApplicationResponse {
    /// Stores local state associated with an application.
    #[serde(rename = "app-local-state", skip_serializing_if = "Option::is_none")]
    pub app_local_state: Option<ApiApplicationLocalState>,

    /// Stores the global information associated with an application.
    #[serde(rename = "created-app", skip_serializing_if = "Option::is_none")]
    pub created_app: Option<ApiApplicationParams>,

    /// The round for which this information is relevant.
    pub round: u64,
}

// ---------------------------------------------------------------------------
// ApplicationResponse / AssetResponse (aliases for endpoint responses)
// ---------------------------------------------------------------------------

/// Response for the `/v2/applications/{application-id}` endpoint.
///
/// Matches go-algorand's `model.ApplicationResponse = Application`.
pub type ApplicationResponse = ApiApplication;

/// Response for the `/v2/assets/{asset-id}` endpoint.
///
/// Matches go-algorand's `model.AssetResponse = Asset`.
pub type AssetResponse = ApiAsset;

// ---------------------------------------------------------------------------
// BlockHashResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/blocks/{round}/hash` endpoint.
///
/// Matches go-algorand's `model.BlockHashResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHashResponse {
    /// Block header hash, base32-encoded (no padding).
    #[serde(rename = "blockHash")]
    pub block_hash: String,
}

// ---------------------------------------------------------------------------
// BlockTxidsResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/blocks/{round}/txids` endpoint.
///
/// Matches go-algorand's `model.BlockTxidsResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTxidsResponse {
    /// Transaction IDs in the block, base32-encoded (no padding).
    #[serde(rename = "blockTxids")]
    pub block_txids: Vec<String>,
}

// ---------------------------------------------------------------------------
// BlockLogsResponse / AppCallLogs
// ---------------------------------------------------------------------------

/// Logs from an app call, including the outer transaction ID and app index.
///
/// Matches go-algorand's `model.AppCallLogs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCallLogs {
    /// The application from which the logs were generated.
    #[serde(rename = "application-index")]
    pub application_index: u64,

    /// An array of logs (each log is base64-encoded bytes).
    #[serde(with = "base64_bytes_array")]
    pub logs: Vec<Vec<u8>>,

    /// The transaction ID of the outer app call that lead to these logs.
    #[serde(rename = "txId")]
    pub tx_id: String,
}

/// Response for the `/v2/blocks/{round}/logs` endpoint.
///
/// Matches go-algorand's `model.BlockLogsResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockLogsResponse {
    pub logs: Vec<AppCallLogs>,
}

// ---------------------------------------------------------------------------
// TransactionProofResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/blocks/{round}/transactions/{txid}/proof` endpoint.
///
/// Matches go-algorand's `model.TransactionProofResponse` (aliased from
/// `model.TransactionProof`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProofResponse {
    /// The type of hash function used to create the proof, must be one of:
    /// * sha512_256
    /// * sha256
    pub hashtype: String,

    /// Index of the transaction in the block's payset.
    pub idx: u64,

    /// Proof of transaction membership, base64 encoded.
    #[serde(with = "base64_bytes")]
    pub proof: Vec<u8>,

    /// Hash of SignedTxnInBlock for verifying proof, base64 encoded.
    #[serde(with = "base64_bytes")]
    pub stibhash: Vec<u8>,

    /// Represents the depth of the tree that is being proven, i.e. the number
    /// of edges from a leaf to the root.
    pub treedepth: u64,
}

// ---------------------------------------------------------------------------
// LightBlockHeaderProofResponse
// ---------------------------------------------------------------------------

/// Response for the `/v2/blocks/{round}/lightheader/proof` endpoint.
///
/// Matches go-algorand's `model.LightBlockHeaderProofResponse` (aliased from
/// `model.LightBlockHeaderProof`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBlockHeaderProofResponse {
    /// The index of the light block header in the vector commitment tree.
    pub index: u64,

    /// The encoded proof of membership, base64 encoded.
    #[serde(with = "base64_bytes")]
    pub proof: Vec<u8>,

    /// Represents the depth of the tree that is being proven, i.e. the number
    /// of edges from a leaf to the root.
    pub treedepth: u64,
}

// ---------------------------------------------------------------------------
// Box / BoxDescriptor / BoxesResponse
// ---------------------------------------------------------------------------

/// Box name and its content.
///
/// Matches go-algorand's `model.Box` (aliased as `BoxResponse`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxResponse {
    /// The box name, base64 encoded.
    #[serde(with = "base64_bytes")]
    pub name: Vec<u8>,

    /// The round for which this information is relevant.
    pub round: u64,

    /// The box value, base64 encoded.
    #[serde(with = "base64_bytes")]
    pub value: Vec<u8>,
}

/// Box descriptor describes a Box.
///
/// Matches go-algorand's `model.BoxDescriptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxDescriptor {
    /// Base64 encoded box name.
    #[serde(with = "base64_bytes")]
    pub name: Vec<u8>,

    /// Base64 encoded box value. Present only when the `values` query
    /// parameter is set to true (pagination mode only).
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub value: Option<Vec<u8>>,
}

/// Response for the `/v2/applications/{application-id}/boxes` endpoint.
///
/// Matches go-algorand's `model.BoxesResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxesResponse {
    pub boxes: Vec<BoxDescriptor>,

    /// Used for pagination: when making another request, provide this
    /// token as the `next` parameter. The next token is the box name to
    /// use as the pagination cursor, encoded in the goal app call arg
    /// form. Only present in pagination mode when more results exist.
    #[serde(rename = "next-token", skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,

    /// The round for which this information is relevant. Only present in
    /// pagination mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u64>,
}

// ---------------------------------------------------------------------------
// BlockResponse (for GET /v2/blocks/{round})
// ---------------------------------------------------------------------------

/// Response for the `GET /v2/blocks/{round}` endpoint (JSON mode, full block).
///
/// Matches go-algorand's `BlockResponseJSON` which wraps the block in a
/// `{"block": ...}` envelope.
///
/// **Note:** The certificate (`cert`) is intentionally omitted for JSON
/// responses.  go-algorand only includes the certificate in the msgpack
/// format response (via `rpcs.RawBlockBytes`).  See the comment in
/// `handlers.go` at `GetBlock`: "Currently, the certificate is only
/// returned in messagepack format requests for a complete block."
///
/// For msgpack mode, the handler returns raw bytes directly with the
/// `X-Algorand-Struct: block-v1` header, bypassing this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockJsonResponse {
    /// The block content.
    pub block: algo_types::Block,
}

/// Response for the `GET /v2/blocks/{round}?header-only=true` endpoint.
///
/// Matches go-algorand's header-only response which wraps the block header
/// in a `{"block": ...}` envelope (same field name as the full block response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderJsonResponse {
    /// The block header content.
    pub block: algo_types::BlockHeader,
}

// ---------------------------------------------------------------------------
// Serde helpers for base64-encoded byte fields
// ---------------------------------------------------------------------------

/// Serde helper for serializing/deserializing `Vec<u8>` as standard base64.
///
/// In go-algorand, `[]byte` fields are automatically base64-encoded in JSON.
pub mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Conversion functions: internal types → API models
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;

use algo_types::{
    AccountData, AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams,
    ConsensusParams, SignedTransaction, TealValue,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::node::AccountLookup;

/// Return `None` for an empty vector, mirroring go's omitempty on `*[]T` fields
/// (an empty slice is omitted, not serialized as `[]`).
fn none_if_empty<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Convert an `AccountLookup` to an `AccountResponse`, matching go-algorand's
/// `AccountDataToAccount` logic.
///
/// When `exclude == "all"`, resource lists (assets, created-assets,
/// apps-local-state, created-apps) are omitted.
pub fn account_data_to_response(
    lookup: &AccountLookup,
    addr: &Address,
    exclude: &str,
    exclude_created_apps_params: bool,
    exclude_created_assets_params: bool,
    consensus: &ConsensusParams,
) -> AccountResponse {
    let record = &lookup.account_data;
    let addr_str = addr.to_algorand_string();

    // pending_rewards = amount - amount_without_pending_rewards (saturating)
    let pending_rewards = record
        .micro_algos
        .saturating_sub(lookup.amount_without_pending_rewards);

    // Status string
    let status = match record.status {
        AccountStatus::Offline => "Offline".to_string(),
        AccountStatus::Online => "Online".to_string(),
        // Matches go's `Status.String()` (`data/basics/userBalance.go`) --
        // note the space. Live-verified against go-algorand v4.6.0-stable
        // (issue #129): `GET /v2/accounts/{fee-sink}` reports
        // `"status": "Not Participating"`.
        AccountStatus::NotParticipating => "Not Participating".to_string(),
    };

    // Participation
    let participation = record.vote_id.and_then(|vote_id| {
        // vote_id being all zeros means "empty" (no participation)
        if vote_id == [0u8; 32] {
            return None;
        }
        let mut p = ApiAccountParticipation {
            vote_participation_key: vote_id.to_vec(),
            selection_participation_key: record.selection_id.unwrap_or([0u8; 32]).to_vec(),
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            state_proof_key: None,
        };
        if let Some(sp_id) = &record.state_proof_id {
            if sp_id.iter().any(|&b| b != 0) {
                p.state_proof_key = Some(sp_id.to_vec());
            }
        }
        Some(p)
    });

    // Auth addr
    let auth_addr = record
        .auth_addr
        .filter(|a| !a.is_zero())
        .map(|a| a.to_algorand_string());

    // Min balance computation matching go-algorand's MinBalance function
    let min_balance = compute_min_balance(record, consensus);

    // omitEmpty helpers
    let omit_empty_u64 = |v: u64| -> Option<u64> {
        if v == 0 {
            None
        } else {
            Some(v)
        }
    };
    let omit_empty_bool = |v: bool| -> Option<bool> {
        if !v {
            None
        } else {
            Some(v)
        }
    };

    // Total app schema. go renders this as `*model.ApplicationStateSchema` with
    // omitempty + RecursiveEmptyCheck, so a zero schema is omitted entirely.
    let apps_total_schema =
        if record.total_app_schema.num_byte_slice == 0 && record.total_app_schema.num_uint == 0 {
            None
        } else {
            Some(ApiApplicationStateSchema {
                num_byte_slice: record.total_app_schema.num_byte_slice,
                num_uint: record.total_app_schema.num_uint,
            })
        };

    let total_extra_pages = record.total_extra_app_pages as u64;

    // For exclude == "all", we skip resource lists but still include counts
    // (matching go-algorand's basicAccountInformation)
    if exclude == "all" {
        return AccountResponse {
            address: addr_str,
            amount: record.micro_algos,
            amount_without_pending_rewards: lookup.amount_without_pending_rewards,
            pending_rewards,
            rewards: record.rewarded_micro_algos,
            status,
            round: lookup.last_round,
            sig_type: None,
            reward_base: omit_empty_u64(record.rewards_base),
            participation,
            incentive_eligible: omit_empty_bool(record.incentive_eligible),
            auth_addr,
            assets: None,
            created_assets: None,
            apps_local_state: None,
            created_apps: None,
            apps_total_schema,
            apps_total_extra_pages: omit_empty_u64(total_extra_pages),
            total_assets_opted_in: record.total_assets_opted_in,
            total_created_assets: record.total_created_assets,
            total_apps_opted_in: record.total_apps_opted_in,
            total_created_apps: record.total_created_apps,
            total_boxes: omit_empty_u64(record.total_boxes),
            total_box_bytes: omit_empty_u64(record.total_box_bytes),
            min_balance,
            last_proposed: omit_empty_u64(record.last_proposed),
            last_heartbeat: omit_empty_u64(record.last_heartbeat),
        };
    }

    // Full response: include all resource lists populated from lookup maps.
    // Matching go-algorand's AccountDataToAccount which iterates per-resource maps.

    // Asset holdings, sorted by asset ID (BTreeMap is already sorted)
    let assets: Vec<ApiAssetHolding> = lookup
        .assets
        .iter()
        .map(|(&id, holding)| asset_holding_to_api(id, holding))
        .collect();

    // Created assets, sorted by asset ID. `exclude=created-assets-params`
    // (go-algorand v4.6.0-stable, issue #507) returns the index only.
    let created_assets: Vec<ApiCreatedAsset> = lookup
        .created_assets
        .iter()
        .map(|(&id, params)| {
            if exclude_created_assets_params {
                ApiCreatedAsset {
                    index: id,
                    params: None,
                }
            } else {
                let asset = asset_params_to_api(id, &addr_str, params);
                ApiCreatedAsset {
                    index: asset.index,
                    params: Some(asset.params),
                }
            }
        })
        .collect();

    // App local states, sorted by app ID
    let apps_local_state: Vec<ApiApplicationLocalState> = lookup
        .app_local_states
        .iter()
        .map(|(&id, state)| app_local_state_to_api(id, state))
        .collect();

    // Created apps, sorted by app ID. `exclude=created-apps-params`
    // (go-algorand v4.6.0-stable, issue #507) returns the ID only.
    let created_apps: Vec<ApiCreatedApplication> = lookup
        .created_apps
        .iter()
        .map(|(&id, params)| {
            if exclude_created_apps_params {
                ApiCreatedApplication { id, params: None }
            } else {
                let app = app_params_to_api(id, &addr_str, params);
                ApiCreatedApplication {
                    id: app.id,
                    params: Some(app.params),
                }
            }
        })
        .collect();

    AccountResponse {
        address: addr_str,
        amount: record.micro_algos,
        amount_without_pending_rewards: lookup.amount_without_pending_rewards,
        pending_rewards,
        rewards: record.rewarded_micro_algos,
        status,
        round: lookup.last_round,
        sig_type: None,
        reward_base: omit_empty_u64(record.rewards_base),
        participation,
        incentive_eligible: omit_empty_bool(record.incentive_eligible),
        auth_addr,
        // go renders these as `*[]…` with omitempty, so empty resource lists
        // are omitted entirely (not serialized as `[]`).
        assets: none_if_empty(assets),
        created_assets: none_if_empty(created_assets),
        apps_local_state: none_if_empty(apps_local_state),
        created_apps: none_if_empty(created_apps),
        apps_total_schema,
        apps_total_extra_pages: omit_empty_u64(total_extra_pages),
        total_assets_opted_in: record.total_assets_opted_in,
        total_created_assets: record.total_created_assets,
        total_apps_opted_in: record.total_apps_opted_in,
        total_created_apps: record.total_created_apps,
        total_boxes: omit_empty_u64(record.total_boxes),
        total_box_bytes: omit_empty_u64(record.total_box_bytes),
        min_balance,
        last_proposed: omit_empty_u64(record.last_proposed),
        last_heartbeat: omit_empty_u64(record.last_heartbeat),
    }
}

/// Compute the minimum balance for an account, matching go-algorand's
/// `MinBalance` function in `data/basics/userBalance.go`.
fn compute_min_balance(record: &AccountData, consensus: &ConsensusParams) -> u64 {
    let mut min = consensus.min_balance;

    // Per-asset cost (asset holdings already include created assets,
    // so we only count total_assets_opted_in, matching go-algorand's
    // MinBalance which uses TotalAssets alone).
    let asset_cost = consensus
        .min_balance
        .saturating_mul(record.total_assets_opted_in);
    min = min.saturating_add(asset_cost);

    // Per-created-app cost
    let app_creation_cost = consensus
        .app_flat_params_min_balance
        .saturating_mul(record.total_created_apps);
    min = min.saturating_add(app_creation_cost);

    // Per-opted-in-app cost
    let app_opt_in_cost = consensus
        .app_flat_opt_in_min_balance
        .saturating_mul(record.total_apps_opted_in);
    min = min.saturating_add(app_opt_in_cost);

    // Schema cost
    let schema = &record.total_app_schema;
    let num_entries = schema.num_uint.saturating_add(schema.num_byte_slice);
    let flat_cost = consensus
        .schema_min_balance_per_entry
        .saturating_mul(num_entries);
    let uint_cost = consensus
        .schema_uint_min_balance
        .saturating_mul(schema.num_uint);
    let bytes_cost = consensus
        .schema_bytes_min_balance
        .saturating_mul(schema.num_byte_slice);
    let schema_cost = flat_cost
        .saturating_add(uint_cost)
        .saturating_add(bytes_cost);
    min = min.saturating_add(schema_cost);

    // Extra app pages cost
    let extra_pages_cost = consensus
        .app_flat_params_min_balance
        .saturating_mul(record.total_extra_app_pages as u64);
    min = min.saturating_add(extra_pages_cost);

    // Box costs
    let box_base_cost = consensus
        .box_flat_min_balance
        .saturating_mul(record.total_boxes);
    min = min.saturating_add(box_base_cost);

    let box_byte_cost = consensus
        .box_byte_min_balance
        .saturating_mul(record.total_box_bytes);
    min = min.saturating_add(box_byte_cost);

    min
}

/// Convert an `AssetHolding` to `ApiAssetHolding`.
pub fn asset_holding_to_api(asset_id: u64, holding: &AssetHolding) -> ApiAssetHolding {
    ApiAssetHolding {
        amount: holding.amount,
        asset_id,
        is_frozen: holding.frozen,
    }
}

/// Check if a string is valid, printable UTF-8. Returns the string if all
/// characters are printable unicode, otherwise returns empty string.
/// Matches go-algorand's `printableUTF8OrEmpty`.
fn printable_utf8_or_empty(s: &str) -> String {
    for c in s.chars() {
        if c == char::REPLACEMENT_CHARACTER || !is_printable(c) {
            return String::new();
        }
    }
    s.to_string()
}

/// Check if a character is printable (matching Go's `unicode.IsPrint`).
///
/// Go's `unicode.IsPrint` returns true for graphic characters (Letters, Marks,
/// Numbers, Punctuation, Symbols) and space separators (Zs category), but NOT
/// for control characters, format characters (Cf), line/paragraph separators
/// (Zl/Zp), or other non-graphic categories.
fn is_printable(c: char) -> bool {
    if c.is_ascii() {
        // ASCII printable: space (0x20) through tilde (0x7E)
        (' '..='~').contains(&c)
    } else {
        // For non-ASCII: exclude control chars and common Unicode format/separator
        // characters that Go's unicode.IsPrint rejects.
        !(c.is_control()
            || ('\u{200B}'..='\u{200F}').contains(&c) // zero-width and directional marks
            || ('\u{2028}'..='\u{2029}').contains(&c) // line/paragraph separator
            || ('\u{202A}'..='\u{202E}').contains(&c) // directional formatting
            || ('\u{2060}'..='\u{2064}').contains(&c) // invisible operators
            || c == '\u{FEFF}' // BOM / zero-width no-break space
            || c == '\u{00AD}') // soft hyphen (Cf)
    }
}

/// Convert `AssetParams` to `ApiAsset`, matching go-algorand's `AssetParamsToAsset`.
pub fn asset_params_to_api(asset_id: u64, creator: &str, params: &AssetParams) -> ApiAsset {
    let frozen = params.default_frozen;

    let name = {
        let s = printable_utf8_or_empty(&params.asset_name);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };
    let name_b64 = if params.asset_name.is_empty() {
        None
    } else {
        Some(params.asset_name.as_bytes().to_vec())
    };

    let unit_name = {
        let s = printable_utf8_or_empty(&params.unit_name);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };
    let unit_name_b64 = if params.unit_name.is_empty() {
        None
    } else {
        Some(params.unit_name.as_bytes().to_vec())
    };

    let url = {
        let s = printable_utf8_or_empty(&params.url);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };
    let url_b64 = if params.url.is_empty() {
        None
    } else {
        Some(params.url.as_bytes().to_vec())
    };

    let metadata_hash = params
        .metadata_hash
        .filter(|h| *h != [0u8; 32])
        .map(|h| h.to_vec());

    let addr_or_nil = |a: &Option<Address>| -> Option<String> {
        a.filter(|addr| !addr.is_zero())
            .map(|addr| addr.to_algorand_string())
    };

    ApiAsset {
        index: asset_id,
        params: ApiAssetParams {
            creator: creator.to_string(),
            total: params.total,
            decimals: params.decimals as u64,
            default_frozen: Some(frozen),
            name,
            name_b64,
            unit_name,
            unit_name_b64,
            url,
            url_b64,
            clawback: addr_or_nil(&params.clawback),
            freeze: addr_or_nil(&params.freeze),
            manager: addr_or_nil(&params.manager),
            reserve: addr_or_nil(&params.reserve),
            metadata_hash,
        },
    }
}

/// Convert `AppParams` to `ApiApplication`, matching go-algorand's
/// `AppParamsToApplication`.
///
/// The `creator` parameter is the Algorand address string of the app creator,
/// passed separately (matching go-algorand's `GetCreator()` pattern) rather
/// than being extracted from `params.creator`.
pub fn app_params_to_api(app_id: u64, creator: &str, params: &AppParams) -> ApiApplication {
    let global_state = convert_teal_key_value(&params.global_state);
    let extra_program_pages = {
        let v = params.extra_program_pages as u64;
        if v == 0 {
            None
        } else {
            Some(v)
        }
    };

    ApiApplication {
        id: app_id,
        params: ApiApplicationParams {
            creator: creator.to_string(),
            approval_program: params.approval_program.clone(),
            clear_state_program: params.clear_state_program.clone(),
            extra_program_pages,
            global_state,
            local_state_schema: Some(ApiApplicationStateSchema {
                num_byte_slice: params.local_state_schema.num_byte_slice,
                num_uint: params.local_state_schema.num_uint,
            }),
            global_state_schema: Some(ApiApplicationStateSchema {
                num_byte_slice: params.global_state_schema.num_byte_slice,
                num_uint: params.global_state_schema.num_uint,
            }),
            // version and size_sponsor are not yet tracked in our internal
            // AppParams; set to None (omitted in JSON via skip_serializing_if).
            version: None,
            size_sponsor: None,
        },
    }
}

/// Convert `AppLocalState` to `ApiApplicationLocalState`, matching
/// go-algorand's `AppLocalState` conversion.
pub fn app_local_state_to_api(app_id: u64, state: &AppLocalState) -> ApiApplicationLocalState {
    let key_value = convert_teal_key_value(&state.key_value);
    ApiApplicationLocalState {
        id: app_id,
        key_value,
        schema: ApiApplicationStateSchema {
            num_byte_slice: state.schema.num_byte_slice,
            num_uint: state.schema.num_uint,
        },
    }
}

/// Convert a `BTreeMap<Vec<u8>, TealValue>` to `TealKeyValueStore`, matching
/// go-algorand's `convertTKVToGenerated`.
///
/// Keys are base64-encoded bytes, sorted by raw key bytes.
pub fn convert_teal_key_value(kv: &BTreeMap<Vec<u8>, TealValue>) -> Option<TealKeyValueStore> {
    if kv.is_empty() {
        return None;
    }

    // BTreeMap is already sorted by key, so we can iterate in order
    let converted: TealKeyValueStore = kv
        .iter()
        .map(|(k, v)| {
            let (value_type, uint, bytes) = match v {
                TealValue::Uint(u) => (2u64, *u, String::new()),
                TealValue::Bytes(b) => (1u64, 0u64, STANDARD.encode(b)),
            };
            ApiTealKeyValue {
                key: STANDARD.encode(k),
                value: ApiTealValue {
                    value_type,
                    uint,
                    bytes,
                },
            }
        })
        .collect();

    Some(converted)
}

/// Serde helper for serializing/deserializing `Vec<Vec<u8>>` as an array of
/// standard base64 strings.
///
/// In go-algorand, `[][]byte` fields (like `AppCallLogs.Logs`) are serialized
/// as JSON arrays of base64-encoded strings.
mod base64_bytes_array {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(items: &Vec<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for item in items {
            seq.serialize_element(&STANDARD.encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let strings: Vec<String> = Vec::deserialize(d)?;
        strings
            .into_iter()
            .map(|s| STANDARD.decode(&s).map_err(serde::de::Error::custom))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Supply response
// ---------------------------------------------------------------------------

/// Response for `GET /v2/ledger/supply`.
///
/// Matches go-algorand's `model.SupplyResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyResponse {
    /// The round at which the supply was computed.
    pub current_round: u64,
    /// Total money of online accounts, in microAlgos.
    #[serde(rename = "online-money")]
    pub online_money: u64,
    /// Online stake used by agreement to vote for `current_round` -- the
    /// lookback-round (`BalanceRound`) online circulation, distinct from
    /// `online_money` (`current_round`'s own online total). Added in
    /// go-algorand v4.6.0-stable (issue #508).
    #[serde(rename = "online-stake")]
    pub online_stake: u64,
    /// Total money of participating accounts, in microAlgos.
    #[serde(rename = "total-money")]
    pub total_money: u64,
}

// ---------------------------------------------------------------------------
// State proof response
// ---------------------------------------------------------------------------

/// Response for `GET /v2/stateproofs/:round`.
///
/// Matches go-algorand's `model.StateProofResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StateProofResponse {
    /// The state proof message.
    pub message: StateProofMessage,
    /// The msgpack-encoded state proof, base64-encoded in JSON.
    #[serde(with = "base64_bytes")]
    pub state_proof: Vec<u8>,
}

/// State proof message fields.
///
/// Matches go-algorand's `model.StateProofMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StateProofMessage {
    /// Block headers commitment, base64-encoded in JSON.
    #[serde(with = "base64_bytes")]
    pub block_headers_commitment: Vec<u8>,
    /// First attested round.
    pub first_attested_round: u64,
    /// Last attested round.
    pub last_attested_round: u64,
    /// Natural log of proven weight.
    pub ln_proven_weight: u64,
    /// Voters commitment, base64-encoded in JSON.
    #[serde(with = "base64_bytes")]
    pub voters_commitment: Vec<u8>,
}

/// Serde helper for serializing/deserializing `Option<Vec<u8>>` as standard
/// base64 (skipped when `None`).
mod optional_base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_str(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => STANDARD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// PostTransactionsResponse
// ---------------------------------------------------------------------------

/// Response for `POST /v2/transactions`.
///
/// Matches go-algorand's `model.PostTransactionsResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostTransactionsResponse {
    /// Encoding of the transaction hash.
    #[serde(rename = "txId")]
    pub tx_id: String,
}

// ---------------------------------------------------------------------------
// PendingTransactionsResponse
// ---------------------------------------------------------------------------

/// Response for `GET /v2/transactions/pending` and
/// `GET /v2/accounts/{address}/transactions/pending`.
///
/// Matches go-algorand's inline response struct in `getPendingTransactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransactionsResponse {
    /// An array of signed transaction objects.
    #[serde(rename = "top-transactions")]
    pub top_transactions: Vec<SignedTransaction>,

    /// Total number of transactions in the pool.
    #[serde(rename = "total-transactions")]
    pub total_transactions: u64,
}

// ---------------------------------------------------------------------------
// EvalDelta / StateDelta types for pending txn response
// ---------------------------------------------------------------------------

/// Represents a TEAL value delta in a state change.
///
/// Matches go-algorand's `model.EvalDelta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvalDelta {
    /// Delta action: 1 = SetBytes, 2 = SetUint, 3 = Delete.
    pub action: u64,

    /// Base64-encoded bytes value (omitted when empty).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,

    /// Uint value (omitted when 0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uint: Option<u64>,
}

/// A key-value pair in a state delta.
///
/// Matches go-algorand's `model.EvalDeltaKeyValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalDeltaKeyValue {
    /// Base64-encoded state key.
    pub key: String,

    /// The value delta.
    pub value: ApiEvalDelta,
}

/// Application state delta (array of key-value pairs).
///
/// Matches go-algorand's `model.StateDelta = []EvalDeltaKeyValue`.
pub type StateDelta = Vec<EvalDeltaKeyValue>;

/// Per-account application state delta.
///
/// Matches go-algorand's `model.AccountStateDelta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStateDelta {
    /// The account address.
    pub address: String,

    /// Application state delta for this account.
    pub delta: StateDelta,
}

// ---------------------------------------------------------------------------
// PreEncodedTxInfo
// ---------------------------------------------------------------------------

/// Pre-encoded pending transaction information.
///
/// Matches go-algorand's `PreEncodedTxInfo` struct in handlers.go.
/// Used for `GET /v2/transactions/pending/{txid}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreEncodedTxInfo {
    /// The signed transaction.
    pub txn: SignedTransaction,

    /// Non-empty when the transaction was kicked from the pool.
    #[serde(rename = "pool-error")]
    pub pool_error: String,

    /// The round in which this transaction was confirmed (omitted if pending).
    #[serde(rename = "confirmed-round", skip_serializing_if = "Option::is_none")]
    pub confirmed_round: Option<u64>,

    /// Closing amount in microAlgos.
    #[serde(rename = "closing-amount", skip_serializing_if = "Option::is_none")]
    pub closing_amount: Option<u64>,

    /// Asset closing amount.
    #[serde(
        rename = "asset-closing-amount",
        skip_serializing_if = "Option::is_none"
    )]
    pub asset_closing_amount: Option<u64>,

    /// Rewards to sender.
    #[serde(rename = "sender-rewards", skip_serializing_if = "Option::is_none")]
    pub sender_rewards: Option<u64>,

    /// Rewards to receiver.
    #[serde(rename = "receiver-rewards", skip_serializing_if = "Option::is_none")]
    pub receiver_rewards: Option<u64>,

    /// Rewards to close-to address.
    #[serde(rename = "close-rewards", skip_serializing_if = "Option::is_none")]
    pub close_rewards: Option<u64>,

    /// Created/configured asset index.
    #[serde(rename = "asset-index", skip_serializing_if = "Option::is_none")]
    pub asset_index: Option<u64>,

    /// Created application index.
    #[serde(rename = "application-index", skip_serializing_if = "Option::is_none")]
    pub application_index: Option<u64>,

    /// Global state delta.
    #[serde(rename = "global-state-delta", skip_serializing_if = "Option::is_none")]
    pub global_state_delta: Option<StateDelta>,

    /// Local state deltas.
    #[serde(rename = "local-state-delta", skip_serializing_if = "Option::is_none")]
    pub local_state_delta: Option<Vec<AccountStateDelta>>,

    /// Logs from application execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<Vec<Vec<u8>>>,

    /// Inner transactions.
    #[serde(rename = "inner-txns", skip_serializing_if = "Option::is_none")]
    pub inner_txns: Option<Vec<PreEncodedTxInfo>>,
}

// ---------------------------------------------------------------------------
// Simulate endpoint types
// ---------------------------------------------------------------------------

/// Trace configuration for simulation execution traces.
///
/// Matches go-algorand's `model.SimulateTraceConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimulateTraceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,

    #[serde(rename = "scratch-change", skip_serializing_if = "Option::is_none")]
    pub scratch_change: Option<bool>,

    #[serde(rename = "stack-change", skip_serializing_if = "Option::is_none")]
    pub stack_change: Option<bool>,

    #[serde(rename = "state-change", skip_serializing_if = "Option::is_none")]
    pub state_change: Option<bool>,
}

/// A transaction group in a simulate request.
///
/// Matches go-algorand's `model.SimulateRequestTransactionGroup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRequestTransactionGroup {
    /// Signed transactions in this group. Uses `serde_json::Value` to match
    /// go-algorand's `json.RawMessage` -- the handler handles msgpack
    /// decoding separately.
    pub txns: Vec<serde_json::Value>,
}

/// Request body for `POST /v2/transactions/simulate`.
///
/// Matches go-algorand's `model.SimulateRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateRequest {
    #[serde(
        rename = "allow-empty-signatures",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_empty_signatures: Option<bool>,

    #[serde(rename = "allow-more-logging", skip_serializing_if = "Option::is_none")]
    pub allow_more_logging: Option<bool>,

    #[serde(
        rename = "allow-unnamed-resources",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_unnamed_resources: Option<bool>,

    #[serde(rename = "exec-trace-config", skip_serializing_if = "Option::is_none")]
    pub exec_trace_config: Option<SimulateTraceConfig>,

    #[serde(
        rename = "extra-opcode-budget",
        skip_serializing_if = "Option::is_none"
    )]
    pub extra_opcode_budget: Option<i64>,

    #[serde(rename = "fix-signers", skip_serializing_if = "Option::is_none")]
    pub fix_signers: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u64>,

    #[serde(rename = "txn-groups")]
    pub txn_groups: Vec<SimulateRequestTransactionGroup>,

    /// Decoded transaction groups. Populated by the handler after decoding
    /// the raw `txns` values into typed `SignedTransaction` structs.
    ///
    /// Not serialized/deserialized from the wire format. The node
    /// implementation should use this field (rather than re-decoding the
    /// raw `txns` values) when building the simulation engine's
    /// `SimulationRequest`.
    #[serde(skip)]
    pub decoded_txn_groups: Vec<Vec<SignedTransaction>>,
}

/// AVM value (bytes or uint).
///
/// Matches go-algorand's `model.AvmValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvmValue {
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub bytes: Option<Vec<u8>>,

    #[serde(rename = "type")]
    pub value_type: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub uint: Option<u64>,
}

/// AVM key-value pair.
///
/// Matches go-algorand's `model.AvmKeyValue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvmKeyValue {
    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,
    pub value: AvmValue,
}

/// Scratch space change from an opcode.
///
/// Matches go-algorand's `model.ScratchChange`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScratchChange {
    #[serde(rename = "new-value")]
    pub new_value: AvmValue,
    pub slot: u64,
}

/// Application state operation (write or delete).
///
/// Matches go-algorand's `model.ApplicationStateOperation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationStateOperation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    #[serde(rename = "app-state-type")]
    pub app_state_type: String,

    #[serde(with = "base64_bytes")]
    pub key: Vec<u8>,

    #[serde(rename = "new-value", skip_serializing_if = "Option::is_none")]
    pub new_value: Option<AvmValue>,

    pub operation: String,
}

/// A single opcode trace unit within an execution trace.
///
/// Matches go-algorand's `model.SimulationOpcodeTraceUnit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationOpcodeTraceUnit {
    pub pc: u64,

    #[serde(rename = "scratch-changes", skip_serializing_if = "Option::is_none")]
    pub scratch_changes: Option<Vec<ScratchChange>>,

    #[serde(rename = "spawned-inners", skip_serializing_if = "Option::is_none")]
    pub spawned_inners: Option<Vec<u64>>,

    #[serde(rename = "stack-additions", skip_serializing_if = "Option::is_none")]
    pub stack_additions: Option<Vec<AvmValue>>,

    #[serde(rename = "stack-pop-count", skip_serializing_if = "Option::is_none")]
    pub stack_pop_count: Option<u64>,

    #[serde(rename = "state-changes", skip_serializing_if = "Option::is_none")]
    pub state_changes: Option<Vec<ApplicationStateOperation>>,
}

/// Full execution trace for a simulated transaction.
///
/// Matches go-algorand's `model.SimulationTransactionExecTrace`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationTransactionExecTrace {
    #[serde(
        rename = "approval-program-hash",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub approval_program_hash: Option<Vec<u8>>,

    #[serde(
        rename = "approval-program-trace",
        skip_serializing_if = "Option::is_none"
    )]
    pub approval_program_trace: Option<Vec<SimulationOpcodeTraceUnit>>,

    #[serde(
        rename = "clear-state-program-hash",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub clear_state_program_hash: Option<Vec<u8>>,

    #[serde(
        rename = "clear-state-program-trace",
        skip_serializing_if = "Option::is_none"
    )]
    pub clear_state_program_trace: Option<Vec<SimulationOpcodeTraceUnit>>,

    #[serde(
        rename = "clear-state-rollback",
        skip_serializing_if = "Option::is_none"
    )]
    pub clear_state_rollback: Option<bool>,

    #[serde(
        rename = "clear-state-rollback-error",
        skip_serializing_if = "Option::is_none"
    )]
    pub clear_state_rollback_error: Option<String>,

    #[serde(rename = "inner-trace", skip_serializing_if = "Option::is_none")]
    pub inner_trace: Option<Vec<SimulationTransactionExecTrace>>,

    #[serde(
        rename = "logic-sig-hash",
        skip_serializing_if = "Option::is_none",
        with = "optional_base64_bytes"
    )]
    pub logic_sig_hash: Option<Vec<u8>>,

    #[serde(rename = "logic-sig-trace", skip_serializing_if = "Option::is_none")]
    pub logic_sig_trace: Option<Vec<SimulationOpcodeTraceUnit>>,
}

/// Reference to a local state account+app pair for unnamed resource tracking.
///
/// Matches go-algorand's `model.ApplicationLocalReference`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLocalReference {
    pub account: String,
    pub app: u64,
}

/// Reference to an asset holding (account + asset) for unnamed resource tracking.
///
/// Matches go-algorand's `model.AssetHoldingReference`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetHoldingReference {
    pub account: String,
    pub asset: u64,
}

/// Reference to a box (app + name) for unnamed resource tracking.
///
/// Matches go-algorand's `model.BoxReference`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxReference {
    pub app: u64,
    #[serde(with = "base64_bytes")]
    pub name: Vec<u8>,
}

/// Unnamed resources accessed during simulation.
///
/// Matches go-algorand's `model.SimulateUnnamedResourcesAccessed`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimulateUnnamedResourcesAccessed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<String>>,

    #[serde(rename = "app-locals", skip_serializing_if = "Option::is_none")]
    pub app_locals: Option<Vec<ApplicationLocalReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub apps: Option<Vec<u64>>,

    #[serde(rename = "asset-holdings", skip_serializing_if = "Option::is_none")]
    pub asset_holdings: Option<Vec<AssetHoldingReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<Vec<u64>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub boxes: Option<Vec<BoxReference>>,

    #[serde(rename = "extra-box-refs", skip_serializing_if = "Option::is_none")]
    pub extra_box_refs: Option<u64>,
}

/// Result for a single simulated transaction.
///
/// Matches go-algorand's `model.SimulateTransactionResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateTransactionResult {
    #[serde(
        rename = "app-budget-consumed",
        skip_serializing_if = "Option::is_none"
    )]
    pub app_budget_consumed: Option<u64>,

    #[serde(rename = "exec-trace", skip_serializing_if = "Option::is_none")]
    pub exec_trace: Option<SimulationTransactionExecTrace>,

    /// Total fee actually paid by this transaction and its descendant inner
    /// transactions (recursively summed). A factual report of what was paid
    /// — not a required amount. Matches go-algorand's
    /// `SimulateTransactionResult.FeesPaid` (`fees-paid`). There is
    /// deliberately no per-transaction `usage` field: fees pool across the
    /// group and round up once for the whole tree, so usage is only
    /// actionable at the group level (see
    /// [`SimulateTransactionGroupResult::group_usage`]).
    #[serde(rename = "fees-paid", skip_serializing_if = "Option::is_none")]
    pub fees_paid: Option<u64>,

    #[serde(rename = "fixed-signer", skip_serializing_if = "Option::is_none")]
    pub fixed_signer: Option<String>,

    #[serde(
        rename = "logic-sig-budget-consumed",
        skip_serializing_if = "Option::is_none"
    )]
    pub logic_sig_budget_consumed: Option<u64>,

    #[serde(rename = "txn-result")]
    pub txn_result: PreEncodedTxInfo,

    #[serde(
        rename = "unnamed-resources-accessed",
        skip_serializing_if = "Option::is_none"
    )]
    pub unnamed_resources_accessed: Option<SimulateUnnamedResourcesAccessed>,
}

/// Result for a simulated transaction group.
///
/// Matches go-algorand's `model.SimulateTransactionGroupResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateTransactionGroupResult {
    #[serde(rename = "app-budget-added", skip_serializing_if = "Option::is_none")]
    pub app_budget_added: Option<u64>,

    #[serde(
        rename = "app-budget-consumed",
        skip_serializing_if = "Option::is_none"
    )]
    pub app_budget_consumed: Option<u64>,

    #[serde(rename = "failed-at", skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<Vec<u64>>,

    #[serde(rename = "failure-message", skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,

    /// Total fee usage (in `Micros`, fixed-point 1e6 scale) required by this
    /// group and all descendant inner-transaction groups (recursively
    /// summed). Matches go-algorand's
    /// `SimulateTransactionGroupResult.GroupUsage` (`group-usage`).
    #[serde(rename = "group-usage", skip_serializing_if = "Option::is_none")]
    pub group_usage: Option<u64>,

    /// Total fee actually paid by this group and all descendant
    /// inner-transaction groups (recursively summed). Matches go-algorand's
    /// `SimulateTransactionGroupResult.GroupFeesPaid` (`group-fees-paid`).
    #[serde(rename = "group-fees-paid", skip_serializing_if = "Option::is_none")]
    pub group_fees_paid: Option<u64>,

    #[serde(rename = "txn-results")]
    pub txn_results: Vec<SimulateTransactionResult>,

    #[serde(
        rename = "unnamed-resources-accessed",
        skip_serializing_if = "Option::is_none"
    )]
    pub unnamed_resources_accessed: Option<SimulateUnnamedResourcesAccessed>,
}

/// Eval overrides applied during simulation.
///
/// Matches go-algorand's `model.SimulationEvalOverrides`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimulationEvalOverrides {
    #[serde(
        rename = "allow-empty-signatures",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_empty_signatures: Option<bool>,

    #[serde(
        rename = "allow-unnamed-resources",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_unnamed_resources: Option<bool>,

    #[serde(
        rename = "extra-opcode-budget",
        skip_serializing_if = "Option::is_none"
    )]
    pub extra_opcode_budget: Option<i64>,

    #[serde(rename = "fix-signers", skip_serializing_if = "Option::is_none")]
    pub fix_signers: Option<bool>,

    #[serde(rename = "max-log-calls", skip_serializing_if = "Option::is_none")]
    pub max_log_calls: Option<u64>,

    #[serde(rename = "max-log-size", skip_serializing_if = "Option::is_none")]
    pub max_log_size: Option<u64>,
}

/// KV storage for an application (global, local, or boxes).
///
/// Matches go-algorand's `model.ApplicationKVStorage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationKVStorage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    pub kvs: Vec<AvmKeyValue>,
}

/// Initial states for a single application.
///
/// Matches go-algorand's `model.ApplicationInitialStates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationInitialStates {
    #[serde(rename = "app-boxes", skip_serializing_if = "Option::is_none")]
    pub app_boxes: Option<ApplicationKVStorage>,

    #[serde(rename = "app-globals", skip_serializing_if = "Option::is_none")]
    pub app_globals: Option<ApplicationKVStorage>,

    #[serde(rename = "app-locals", skip_serializing_if = "Option::is_none")]
    pub app_locals: Option<Vec<ApplicationKVStorage>>,

    pub id: u64,
}

/// Initial states snapshot before simulation.
///
/// Matches go-algorand's `model.SimulateInitialStates`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SimulateInitialStates {
    #[serde(rename = "app-initial-states", skip_serializing_if = "Option::is_none")]
    pub app_initial_states: Option<Vec<ApplicationInitialStates>>,
}

/// Response from `POST /v2/transactions/simulate`.
///
/// Matches go-algorand's `model.SimulateResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResponse {
    #[serde(rename = "eval-overrides", skip_serializing_if = "Option::is_none")]
    pub eval_overrides: Option<SimulationEvalOverrides>,

    #[serde(rename = "exec-trace-config", skip_serializing_if = "Option::is_none")]
    pub exec_trace_config: Option<SimulateTraceConfig>,

    #[serde(rename = "initial-states", skip_serializing_if = "Option::is_none")]
    pub initial_states: Option<SimulateInitialStates>,

    #[serde(rename = "last-round")]
    pub last_round: u64,

    #[serde(rename = "txn-groups")]
    pub txn_groups: Vec<SimulateTransactionGroupResult>,

    pub version: u64,
}

// ---------------------------------------------------------------------------
// CompileResponse / DisassembleResponse
// ---------------------------------------------------------------------------

/// Response from `POST /v2/teal/compile`.
///
/// Matches go-algorand's `model.CompileResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileResponse {
    /// Hash of the compiled program, as an Algorand address string.
    pub hash: String,

    /// Base64-encoded compiled program bytes.
    pub result: String,

    /// Source map (only present when `sourcemap=true` query param is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcemap: Option<serde_json::Value>,
}

/// Response from `POST /v2/teal/disassemble`.
///
/// Matches go-algorand's `model.DisassembleResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembleResponse {
    /// The disassembled TEAL source text.
    pub result: String,
}

// ---------------------------------------------------------------------------
// Participation key models
// ---------------------------------------------------------------------------

/// Participation key response — matches go-algorand's `model.ParticipationKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationKey {
    /// The address of the participating account.
    pub address: String,

    /// The effective first valid round for this participation key.
    #[serde(
        rename = "effective-first-valid",
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_first_valid: Option<u64>,

    /// The effective last valid round for this participation key.
    #[serde(
        rename = "effective-last-valid",
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_last_valid: Option<u64>,

    /// The participation key ID (base32-encoded).
    pub id: String,

    /// The account participation information.
    pub key: ApiAccountParticipation,

    /// The last round this key was used to propose a block.
    #[serde(
        rename = "last-block-proposal",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_block_proposal: Option<u64>,

    /// The last round this key was used to generate a state proof.
    #[serde(rename = "last-state-proof", skip_serializing_if = "Option::is_none")]
    pub last_state_proof: Option<u64>,

    /// The last round this key was used to vote.
    #[serde(rename = "last-vote", skip_serializing_if = "Option::is_none")]
    pub last_vote: Option<u64>,
}

/// Response for `POST /v2/participation` — matches go-algorand's
/// `model.PostParticipationResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostParticipationResponse {
    /// The participation key ID.
    #[serde(rename = "partId")]
    pub part_id: String,
}

// ---------------------------------------------------------------------------
// Operational endpoint response types
// ---------------------------------------------------------------------------

/// Response for `POST /v2/catchup/{catchpoint}` — matches go-algorand's
/// `model.CatchpointStartResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchpointStartResponse {
    /// Status message about the catchup operation.
    #[serde(rename = "catchup-message")]
    pub catchup_message: String,
}

/// Response for `DELETE /v2/catchup/{catchpoint}` — matches go-algorand's
/// `model.CatchpointAbortResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchpointAbortResponse {
    /// Status message about the catchup abort operation.
    #[serde(rename = "catchup-message")]
    pub catchup_message: String,
}

/// Response for `GET /v2/node/peers` — matches go-algorand's
/// `model.GetPeersResponse`.
///
/// The top-level JSON key is capitalized `"Peers"` — unusual against the
/// rest of the API's lowercase-hyphenated convention, but that's exactly
/// what go-algorand's OAS3 schema specifies (`algod.oas3.yml` line ~557,
/// `GetPeersResponse.content.application/json.schema.properties.Peers`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPeersResponse {
    /// The connected peers.
    #[serde(rename = "Peers")]
    pub peers: Vec<PeerStatus>,
}

/// The status of a single connected peer — matches go-algorand's
/// `model.PeerStatus`. All three fields are required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    /// `"inbound"` or `"outbound"`.
    #[serde(rename = "connection-type")]
    pub connection_type: String,
    /// The peer's network address.
    #[serde(rename = "network-address")]
    pub network_address: String,
    /// `"p2p"` or `"ws"`.
    #[serde(rename = "network-type")]
    pub network_type: String,
}

/// Response for `GET /v2/ledger/sync` — matches go-algorand's
/// `model.GetSyncRoundResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSyncRoundResponse {
    /// The sync round.
    pub round: u64,
}

/// Response for `GET /v2/devmode/blocks/offset` — matches go-algorand's
/// `model.GetBlockTimeStampOffsetResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockTimeStampOffsetResponse {
    /// The timestamp offset in seconds.
    pub offset: u64,
}

/// Debug profiling settings — matches go-algorand's
/// `model.DebugSettingsProf`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSettingsProf {
    /// The block profiling rate.
    #[serde(rename = "block-rate", skip_serializing_if = "Option::is_none")]
    pub block_rate: Option<u64>,

    /// The mutex profiling rate.
    #[serde(rename = "mutex-rate", skip_serializing_if = "Option::is_none")]
    pub mutex_rate: Option<u64>,
}

// ---------------------------------------------------------------------------
// Experimental API: AccountAssetsInformation
// ---------------------------------------------------------------------------

/// A single asset holding with optional asset params.
///
/// Matches go-algorand's `model.AccountAssetHolding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAssetHolding {
    /// The asset holding information.
    #[serde(rename = "asset-holding")]
    pub asset_holding: ApiAssetHolding,

    /// The asset params (present when the account is the asset creator).
    #[serde(rename = "asset-params", skip_serializing_if = "Option::is_none")]
    pub asset_params: Option<ApiAssetParams>,
}

/// Response for `GET /v2/accounts/{address}/assets` — matches go-algorand's
/// `model.AccountAssetsInformationResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAssetsInformationResponse {
    /// The round at which the lookup was performed.
    pub round: u64,

    /// The asset holdings for this account.
    #[serde(rename = "asset-holdings", skip_serializing_if = "Option::is_none")]
    pub asset_holdings: Option<Vec<AccountAssetHolding>>,

    /// Pagination token for the next page of results.
    #[serde(rename = "next-token", skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}

// ---------------------------------------------------------------------------
// AccountApplicationsInformation (issue #505 — go-algorand v4.6.0-stable)
// ---------------------------------------------------------------------------

/// The account's application resource (local state and params if the
/// account is the creator) for a specific application ID.
///
/// Matches go-algorand's `model.AccountApplicationResource`. Note:
/// go-algorand's own handler never populates `created-at-round` either
/// (see `daemon/algod/api/server/v2/handlers.go`
/// `AccountApplicationsInformation`), so it is omitted here too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountApplicationResource {
    /// The application ID.
    pub id: u64,

    /// Local state, present when the account has opted in.
    #[serde(rename = "app-local-state", skip_serializing_if = "Option::is_none")]
    pub app_local_state: Option<ApiApplicationLocalState>,

    /// Whether the application has been deleted. Only present (and true)
    /// when the app no longer exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,

    /// Application params, present when the account is the creator AND
    /// `include-params` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<ApiApplicationParams>,
}

/// Response for `GET /v2/accounts/{address}/applications` — matches
/// go-algorand's `model.AccountApplicationsInformationResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountApplicationsInformationResponse {
    /// The round at which the lookup was performed.
    pub round: u64,

    /// The application resources for this account.
    #[serde(
        rename = "application-resources",
        skip_serializing_if = "Option::is_none"
    )]
    pub application_resources: Option<Vec<AccountApplicationResource>>,

    /// Pagination token for the next page of results.
    #[serde(rename = "next-token", skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
}
