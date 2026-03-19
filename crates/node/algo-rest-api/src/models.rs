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
    pub created_apps: Option<Vec<ApiApplication>>,

    /// \[apar\] parameters of assets created by this account.
    #[serde(rename = "created-assets", skip_serializing_if = "Option::is_none")]
    pub created_assets: Option<Vec<ApiAsset>>,

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
}

/// Response for the `/v2/applications/{application-id}/boxes` endpoint.
///
/// Matches go-algorand's `model.BoxesResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxesResponse {
    pub boxes: Vec<BoxDescriptor>,
}

// ---------------------------------------------------------------------------
// Serde helpers for base64-encoded byte fields
// ---------------------------------------------------------------------------

/// Serde helper for serializing/deserializing `Vec<u8>` as standard base64.
///
/// In go-algorand, `[]byte` fields are automatically base64-encoded in JSON.
mod base64_bytes {
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
    ConsensusParams, TealValue,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::node::AccountLookup;

/// Convert an `AccountLookup` to an `AccountResponse`, matching go-algorand's
/// `AccountDataToAccount` logic.
///
/// When `exclude == "all"`, resource lists (assets, created-assets,
/// apps-local-state, created-apps) are omitted.
pub fn account_data_to_response(
    lookup: &AccountLookup,
    addr: &Address,
    exclude: &str,
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
        AccountStatus::NotParticipating => "NotParticipating".to_string(),
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

    // Total app schema
    let apps_total_schema = Some(ApiApplicationStateSchema {
        num_byte_slice: record.total_app_schema.num_byte_slice,
        num_uint: record.total_app_schema.num_uint,
    });

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
            reward_base: Some(record.rewards_base),
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

    // Created assets, sorted by asset ID
    let created_assets: Vec<ApiAsset> = lookup
        .created_assets
        .iter()
        .map(|(&id, params)| asset_params_to_api(id, &addr_str, params))
        .collect();

    // App local states, sorted by app ID
    let apps_local_state: Vec<ApiApplicationLocalState> = lookup
        .app_local_states
        .iter()
        .map(|(&id, state)| app_local_state_to_api(id, state))
        .collect();

    // Created apps, sorted by app ID
    let created_apps: Vec<ApiApplication> = lookup
        .created_apps
        .iter()
        .map(|(&id, params)| app_params_to_api(id, &addr_str, params))
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
        reward_base: Some(record.rewards_base),
        participation,
        incentive_eligible: omit_empty_bool(record.incentive_eligible),
        auth_addr,
        assets: Some(assets),
        created_assets: Some(created_assets),
        apps_local_state: Some(apps_local_state),
        created_apps: Some(created_apps),
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
