use std::collections::BTreeMap;
use std::fmt;

use crate::{Address, AssetParams, StateSchema};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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
            AccountStatus::NotParticipating => write!(f, "NotParticipating"),
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
    /// Round at which this account was last modified (Go codec key "z").
    pub update_round: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct AppParams {
    pub creator: Address,
    pub approval_program: Vec<u8>,
    pub clear_state_program: Vec<u8>,
    pub global_state: BTreeMap<Vec<u8>, TealValue>,
    pub local_state_schema: StateSchema,
    pub global_state_schema: StateSchema,
    pub extra_program_pages: u32,
}
