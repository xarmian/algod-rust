use std::path::Path;

use algo_error::AlgoError;
use algo_types::{AccountData, AccountStatus, Address};
use data_encoding::BASE64;
use serde::Deserialize;

use crate::state::LedgerState;

/// Parsed genesis.json representation.
#[derive(Debug, Deserialize)]
pub struct GenesisJson {
    pub network: String,
    pub id: String,
    pub proto: String,
    pub alloc: Vec<GenesisAllocation>,
    pub fees: String,
    pub rwd: String,
}

/// A single account allocation from genesis.json.
#[derive(Debug, Deserialize)]
pub struct GenesisAllocation {
    pub addr: String,
    pub comment: Option<String>,
    pub state: GenesisAccountState,
}

/// Account state fields within a genesis allocation.
#[derive(Debug, Deserialize)]
pub struct GenesisAccountState {
    #[serde(default)]
    pub algo: u64,
    pub onl: Option<u8>,
    pub sel: Option<String>,
    pub vote: Option<String>,
    #[serde(rename = "voteKD")]
    pub vote_kd: Option<u64>,
    #[serde(rename = "voteFst")]
    pub vote_fst: Option<u64>,
    #[serde(rename = "voteLst")]
    pub vote_lst: Option<u64>,
    pub stprf: Option<String>,
}

/// Populate any `LedgerStore` backend from parsed genesis data.
///
/// Sets fee_sink, rewards_pool, genesis_id, protocol, and all account
/// allocations. Can be used with both in-memory `LedgerState` and future
/// SQLite backends.
///
/// TODO: go-algorand computes genesis hash as SHA512/256("GE" || canonical_msgpack(genesis)).
/// For now, genesis_hash is left as [0u8; 32] — the real hash is available from block
/// headers during replay and can be set/verified then.
pub fn populate_store<L: crate::store_trait::LedgerStore>(
    store: &mut L,
    genesis: &GenesisJson,
) -> Result<(), AlgoError> {
    let fee_sink = Address::from_algorand_string(&genesis.fees).map_err(|e| AlgoError::Ledger {
        message: format!("invalid fee sink address '{}': {e}", genesis.fees),
    })?;
    let rewards_pool =
        Address::from_algorand_string(&genesis.rwd).map_err(|e| AlgoError::Ledger {
            message: format!("invalid rewards pool address '{}': {e}", genesis.rwd),
        })?;

    store.set_fee_sink(fee_sink);
    store.set_rewards_pool(rewards_pool);
    store.set_genesis_id(format!("{}-{}", genesis.network, genesis.id));
    store.set_protocol(genesis.proto.clone());

    // Process allocations
    for alloc in &genesis.alloc {
        let addr = Address::from_algorand_string(&alloc.addr).map_err(|e| AlgoError::Ledger {
            message: format!("invalid allocation address '{}': {e}", alloc.addr),
        })?;

        let status = match alloc.state.onl {
            Some(v) => AccountStatus::from(v),
            None => AccountStatus::Offline,
        };

        let vote_id = decode_key_32(&alloc.state.vote, "vote")?;
        let selection_id = decode_key_32(&alloc.state.sel, "sel")?;
        let state_proof_id = decode_key_64(&alloc.state.stprf, "stprf")?;

        let account = AccountData {
            micro_algos: alloc.state.algo,
            status,
            vote_id,
            selection_id,
            state_proof_id,
            vote_first_valid: alloc.state.vote_fst.unwrap_or(0),
            vote_last_valid: alloc.state.vote_lst.unwrap_or(0),
            vote_key_dilution: alloc.state.vote_kd.unwrap_or(0),
            ..Default::default()
        };

        store.set_account(&addr, account);
    }

    Ok(())
}

/// Parse genesis JSON string into its typed representation.
pub fn parse_genesis_json(json_str: &str) -> Result<GenesisJson, AlgoError> {
    serde_json::from_str(json_str).map_err(|e| AlgoError::Ledger {
        message: format!("failed to parse genesis JSON: {e}"),
    })
}

impl LedgerState {
    /// Load ledger state from a genesis.json file on disk.
    pub fn from_genesis(path: &Path) -> Result<LedgerState, AlgoError> {
        let json_str = std::fs::read_to_string(path).map_err(|e| AlgoError::Ledger {
            message: format!("failed to read genesis file {}: {e}", path.display()),
        })?;
        Self::from_genesis_json(&json_str)
    }

    /// Parse a genesis JSON string and build the initial ledger state.
    ///
    /// Populates accounts from allocations, sets fee_sink, rewards_pool,
    /// genesis_id, and protocol version.
    pub fn from_genesis_json(json_str: &str) -> Result<LedgerState, AlgoError> {
        let genesis = parse_genesis_json(json_str)?;
        let mut state = LedgerState::new();
        populate_store(&mut state, &genesis)?;
        Ok(state)
    }
}

/// Decode an optional base64 string into a 32-byte key.
fn decode_key_32(value: &Option<String>, field_name: &str) -> Result<Option<[u8; 32]>, AlgoError> {
    match value {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let bytes = BASE64.decode(s.as_bytes()).map_err(|e| AlgoError::Ledger {
                message: format!("invalid base64 for {field_name}: {e}"),
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| AlgoError::Ledger {
                message: format!("{field_name}: expected 32 bytes, got {}", v.len()),
            })?;
            Ok(Some(arr))
        }
    }
}

/// Decode an optional base64 string into a 64-byte key (state proof key).
fn decode_key_64(value: &Option<String>, field_name: &str) -> Result<Option<[u8; 64]>, AlgoError> {
    match value {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let bytes = BASE64.decode(s.as_bytes()).map_err(|e| AlgoError::Ledger {
                message: format!("invalid base64 for {field_name}: {e}"),
            })?;
            let arr: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| AlgoError::Ledger {
                message: format!("{field_name}: expected 64 bytes, got {}", v.len()),
            })?;
            Ok(Some(arr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_GENESIS: &str = r#"{
        "network": "testnet",
        "id": "v1.0",
        "proto": "https://github.com/algorandfoundation/specs/tree/44fa607d6051730f5264526bf3c108d51f0eadb6",
        "alloc": [
            {
                "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                "comment": "FeeSink",
                "state": { "algo": 100000 }
            },
            {
                "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                "comment": "RewardsPool",
                "state": { "algo": 5000000000 }
            }
        ],
        "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
        "rwd": "7777777777777777777777777777777777777777777777777774MSJUVU"
    }"#;

    #[test]
    fn test_parse_genesis_json() {
        let state = LedgerState::from_genesis_json(SAMPLE_GENESIS).unwrap();
        assert_eq!(state.genesis_id, "testnet-v1.0"); // "testnet" + "-" + "v1.0"
        assert!(!state.fee_sink.is_zero());
        assert!(!state.rewards_pool.is_zero());
        // Last allocation wins (same address written twice)
        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.genesis_hash, [0u8; 32]);
    }

    #[test]
    fn test_parse_genesis_with_online_account() {
        let json = r#"{
            "network": "devnet",
            "id": "v1.0",
            "proto": "test-proto",
            "alloc": [
                {
                    "addr": "7777777777777777777777777777777777777777777777777774MSJUVU",
                    "comment": "Online validator",
                    "state": {
                        "algo": 1000000,
                        "onl": 1,
                        "voteFst": 1,
                        "voteLst": 3000000,
                        "voteKD": 10000
                    }
                }
            ],
            "fees": "7777777777777777777777777777777777777777777777777774MSJUVU",
            "rwd": "7777777777777777777777777777777777777777777777777774MSJUVU"
        }"#;

        let state = LedgerState::from_genesis_json(json).unwrap();
        let addr = Address::from_algorand_string(
            "7777777777777777777777777777777777777777777777777774MSJUVU",
        )
        .unwrap();
        let account = state.get_account(&addr).unwrap();
        assert_eq!(account.status, AccountStatus::Online);
        assert_eq!(account.micro_algos, 1_000_000);
        assert_eq!(account.vote_first_valid, 1);
        assert_eq!(account.vote_last_valid, 3_000_000);
        assert_eq!(account.vote_key_dilution, 10_000);
    }

    #[test]
    fn test_invalid_genesis_json() {
        let result = LedgerState::from_genesis_json("not valid json");
        assert!(result.is_err());
    }
}
