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

use std::collections::BTreeMap;
use std::fmt;

use crate::{Address, AssetParams, StateSchema};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum AccountStatus {
    #[default]
    Offline = 0,
    Online = 1,
    NotParticipating = 2,
}

impl fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountStatus::Offline => write!(f, "Offline"),
            AccountStatus::Online => write!(f, "Online"),
            // Matches go's `Status.String()` exactly (`data/basics/userBalance.go`)
            // — note the space, unlike the enum variant's own Rust name.
            // Live-verified against go-algorand v4.6.0-stable (issue #129):
            // `GET /v2/accounts/{fee-sink}` reports `"status": "Not Participating"`.
            AccountStatus::NotParticipating => write!(f, "Not Participating"),
        }
    }
}

impl From<u8> for AccountStatus {
    fn from(v: u8) -> Self {
        match v {
            0 => AccountStatus::Offline,
            1 => AccountStatus::Online,
            2 => AccountStatus::NotParticipating,
            _ => AccountStatus::Offline,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct AccountData {
    pub micro_algos: u64,
    pub rewards_base: u64,
    pub rewarded_micro_algos: u64,
    pub status: AccountStatus,
    pub vote_id: Option<[u8; 32]>,
    pub selection_id: Option<[u8; 32]>,
    pub state_proof_id: Option<[u8; 64]>,
    pub vote_first_valid: u64,
    pub vote_last_valid: u64,
    pub vote_key_dilution: u64,
    pub auth_addr: Option<Address>,
    pub total_assets_opted_in: u64,
    pub total_created_assets: u64,
    pub total_apps_opted_in: u64,
    pub total_created_apps: u64,
    pub total_extra_app_pages: u32,
    pub total_box_bytes: u64,
    pub total_boxes: u64,
    /// Aggregate of all app schemas (global for created apps, local for opted-in apps).
    /// Used for min-balance computation without iterating per-app schemas.
    pub total_app_schema: StateSchema,
    /// V40+ block payouts eligibility.
    pub incentive_eligible: bool,
    /// Last round this account proposed a block.
    pub last_proposed: u64,
    /// Last heartbeat round.
    pub last_heartbeat: u64,
    /// Round at which this account was last modified (Go codec key "z").
    pub update_round: u64,

    // --- Full resource maps (matching go-algorand basics.AccountData) ---
    /// Created asset parameters, keyed by asset index.
    /// Go codec tag: `"apar"`.
    pub asset_params: BTreeMap<u64, AssetParams>,

    /// Asset holdings (opted-in assets), keyed by asset index.
    /// Go codec tag: `"asset"`.
    pub assets: BTreeMap<u64, AssetHolding>,

    /// App local states (opted-in apps), keyed by app index.
    /// Go codec tag: `"appl"`.
    pub app_local_states: BTreeMap<u64, AppLocalState>,

    /// Created application parameters, keyed by app index.
    /// Go codec tag: `"appp"`.
    pub app_params: BTreeMap<u64, AppParams>,
}

#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct AssetHolding {
    pub amount: u64,
    pub frozen: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssetParamsRecord {
    pub params: AssetParams,
    pub creator: Address,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TealValue {
    Uint(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppLocalState {
    pub schema: StateSchema,
    pub key_value: BTreeMap<Vec<u8>, TealValue>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AppParams {
    pub creator: Address,
    pub approval_program: Vec<u8>,
    pub clear_state_program: Vec<u8>,
    pub global_state: BTreeMap<Vec<u8>, TealValue>,
    pub local_state_schema: StateSchema,
    pub global_state_schema: StateSchema,
    pub extra_program_pages: u32,
    /// Go codec `"v"`. Starts at 0 on create; increments on
    /// `UpdateApplication` when the `EnableAppVersioning` consensus
    /// param is set (go-algorand `ledger/apply/application.go`).
    pub version: u64,
    /// Go codec `"ss"`. The account responsible for the MBR of extra
    /// program pages / global schema, when that differs from the
    /// creator. Zero address means "no sponsor" (creator pays).
    pub size_sponsor: Address,
    /// Go codec `"fbr"`. When `true`, any app may read (but not write)
    /// this app's boxes. Settable via the `app_params_set` opcode
    /// (`AppForeignBoxReads`, `foreignBoxVersion`/v5.0.0-stable).
    pub foreign_box_reads: bool,
    /// Go codec `"fba"`. When `true`, any app (existing or future) with
    /// the same creator as this app may read *and* write this app's
    /// boxes. Settable via the `app_params_set` opcode
    /// (`AppFamilyBoxAccess`, `foreignBoxVersion`/v5.0.0-stable).
    pub family_box_access: bool,
}
