//! Shared transaction field reading logic.
//!
//! Provides `read_txn_field` and `type_enum` which map AVM field indices
//! to values from a `SignedTransaction`.  Used by both `LedgerAvmContext`
//! (in algo-ledger) and `LogicSigAvmContext` (in algo-avm).

use algo_error::AlgoError;
use algo_types::{SignedTransaction, TealValue};

/// Maximum byte string length in the AVM (matches go-algorand `maxStringSize`).
/// Used for program page chunking.
const MAX_STRING_SIZE: usize = 4096;

/// Convert an Algorand transaction type string to its `TypeEnum` integer,
/// matching go-algorand numbering.
pub fn type_enum(txn_type: &str) -> u64 {
    match txn_type {
        "pay" => 1,
        "keyreg" => 2,
        "acfg" => 3,
        "axfer" => 4,
        "afrz" => 5,
        "appl" => 6,
        "stpf" => 7,
        _ => 0,
    }
}

/// Read a transaction field value by AVM field index.
///
/// This is the shared implementation used by both `LedgerAvmContext` and
/// `LogicSigAvmContext`.  Fields that depend on ApplyData (Logs, NumLogs,
/// LastLog, CreatedAssetID, CreatedApplicationID) return empty/zero values
/// here.  Callers that have ApplyData available (e.g. `LedgerAvmContext`)
/// should override those fields in their `txn_field` implementation.
pub fn read_txn_field(
    stxn: &SignedTransaction,
    field: u8,
    array_index: Option<usize>,
    group_index_val: usize,
) -> Result<TealValue, AlgoError> {
    let txn = &stxn.txn;
    match field {
        // Sender
        0 => Ok(TealValue::Bytes(txn.sender.0.to_vec())),
        // Fee
        1 => Ok(TealValue::Uint(txn.fee)),
        // FirstValid
        2 => Ok(TealValue::Uint(txn.first_valid.0)),
        // FirstValidTime — timestamp of block(FirstValid-1). AVM v7+.
        // Requires block history access which is not yet implemented.
        3 => Err(AlgoError::Avm {
            message: "FirstValidTime not yet supported (requires block history access)".to_string(),
        }),
        // LastValid
        4 => Ok(TealValue::Uint(txn.last_valid.0)),
        // Note
        5 => Ok(TealValue::Bytes(txn.note.to_vec())),
        // Lease
        6 => Ok(TealValue::Bytes(txn.lease.to_vec())),
        // Receiver
        7 => Ok(TealValue::Bytes(txn.receiver.0.to_vec())),
        // Amount
        8 => Ok(TealValue::Uint(txn.amount)),
        // CloseRemainderTo
        9 => Ok(TealValue::Bytes(txn.close_remainder_to.0.to_vec())),
        // VotePK
        10 => Ok(TealValue::Bytes(
            txn.vote_pk.as_ref().map(|b| b.to_vec()).unwrap_or_default(),
        )),
        // SelectionPK
        11 => Ok(TealValue::Bytes(
            txn.selection_pk
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // VoteFirst
        12 => Ok(TealValue::Uint(txn.vote_first)),
        // VoteLast
        13 => Ok(TealValue::Uint(txn.vote_last)),
        // VoteKeyDilution
        14 => Ok(TealValue::Uint(txn.vote_key_dilution)),
        // Type
        15 => Ok(TealValue::Bytes(txn.txn_type.as_bytes().to_vec())),
        // TypeEnum
        16 => Ok(TealValue::Uint(type_enum(&txn.txn_type))),
        // XferAsset
        17 => Ok(TealValue::Uint(txn.xaid)),
        // AssetAmount
        18 => Ok(TealValue::Uint(txn.asset_amount)),
        // AssetSender
        19 => Ok(TealValue::Bytes(
            txn.asset_sender
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // AssetReceiver
        20 => Ok(TealValue::Bytes(
            txn.asset_receiver
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // AssetCloseTo
        21 => Ok(TealValue::Bytes(
            txn.asset_close_to
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // GroupIndex
        22 => Ok(TealValue::Uint(group_index_val as u64)),
        // TxID
        23 => {
            // TxID = SHA512/256("TX" || canonical_encode(txn))
            let digest = algo_codec::compute_txn_id(txn);
            Ok(TealValue::Bytes(digest.0.to_vec()))
        }
        // ApplicationID
        24 => Ok(TealValue::Uint(txn.application_id)),
        // OnCompletion
        25 => Ok(TealValue::Uint(txn.on_completion)),
        // ApplicationArgs (array)
        26 => {
            let args = txn.app_arguments.as_deref().unwrap_or(&[]);
            match array_index {
                Some(i) => {
                    if i >= args.len() {
                        Err(AlgoError::Avm {
                            message: format!(
                                "ApplicationArgs index {} out of range (len={})",
                                i,
                                args.len()
                            ),
                        })
                    } else {
                        let val = args[i].as_ref().map(|b| b.to_vec()).unwrap_or_default();
                        Ok(TealValue::Bytes(val))
                    }
                }
                None => Ok(TealValue::Uint(args.len() as u64)),
            }
        }
        // NumAppArgs
        27 => {
            let args = txn.app_arguments.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(args.len() as u64))
        }
        // Accounts (array) — index 0 = sender, 1+ = accounts[i-1]
        28 => {
            let accts = txn.accounts.as_deref().unwrap_or(&[]);
            match array_index {
                Some(0) => Ok(TealValue::Bytes(txn.sender.0.to_vec())),
                Some(i) => {
                    let idx = i - 1;
                    if idx >= accts.len() {
                        Err(AlgoError::Avm {
                            message: format!(
                                "Accounts index {} out of range (len={})",
                                i,
                                accts.len()
                            ),
                        })
                    } else {
                        Ok(TealValue::Bytes(accts[idx].0.to_vec()))
                    }
                }
                None => Ok(TealValue::Uint(accts.len() as u64)),
            }
        }
        // NumAccounts
        29 => {
            let accts = txn.accounts.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(accts.len() as u64))
        }
        // ApprovalProgram
        30 => Ok(TealValue::Bytes(
            txn.approval_program
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ClearStateProgram
        31 => Ok(TealValue::Bytes(
            txn.clear_state_program
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // RekeyTo
        32 => Ok(TealValue::Bytes(
            txn.rekey_to
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAsset
        33 => Ok(TealValue::Uint(txn.config_asset)),
        // ConfigAssetTotal
        34 => Ok(TealValue::Uint(
            txn.asset_params.as_ref().map(|p| p.total).unwrap_or(0),
        )),
        // ConfigAssetDecimals
        35 => Ok(TealValue::Uint(
            txn.asset_params
                .as_ref()
                .map(|p| p.decimals as u64)
                .unwrap_or(0),
        )),
        // ConfigAssetDefaultFrozen
        36 => Ok(TealValue::Uint(
            txn.asset_params
                .as_ref()
                .map(|p| p.default_frozen as u64)
                .unwrap_or(0),
        )),
        // ConfigAssetUnitName
        37 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.unit_name.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetName
        38 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.asset_name.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetURL
        39 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.url.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetMetadataHash
        40 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.metadata_hash.as_ref())
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetManager
        41 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.manager.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetReserve
        42 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.reserve.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetFreeze
        43 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.freeze.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetClawback
        44 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.clawback.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // FreezeAsset
        45 => Ok(TealValue::Uint(txn.freeze_asset)),
        // FreezeAssetAccount
        46 => Ok(TealValue::Bytes(
            txn.freeze_account
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // FreezeAssetFrozen
        47 => Ok(TealValue::Uint(txn.asset_frozen as u64)),
        // Assets (foreign assets array)
        48 => {
            let assets = txn.foreign_assets.as_deref().unwrap_or(&[]);
            match array_index {
                Some(i) => {
                    if i >= assets.len() {
                        Err(AlgoError::Avm {
                            message: format!(
                                "Assets index {} out of range (len={})",
                                i,
                                assets.len()
                            ),
                        })
                    } else {
                        Ok(TealValue::Uint(assets[i]))
                    }
                }
                None => Ok(TealValue::Uint(assets.len() as u64)),
            }
        }
        // NumAssets
        49 => {
            let assets = txn.foreign_assets.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(assets.len() as u64))
        }
        // Applications (foreign apps array) — index 0 = current app ID, 1+ = foreign_apps[i-1]
        50 => {
            let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
            match array_index {
                Some(0) => Ok(TealValue::Uint(txn.application_id)),
                Some(i) => {
                    let idx = i - 1;
                    if idx >= apps.len() {
                        Err(AlgoError::Avm {
                            message: format!(
                                "Applications index {} out of range (len={})",
                                i,
                                apps.len()
                            ),
                        })
                    } else {
                        Ok(TealValue::Uint(apps[idx]))
                    }
                }
                None => Ok(TealValue::Uint(apps.len() as u64)),
            }
        }
        // NumApplications
        51 => {
            let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(apps.len() as u64))
        }
        // GlobalNumUint
        52 => Ok(TealValue::Uint(
            txn.global_state_schema
                .as_ref()
                .map(|s| s.num_uint)
                .unwrap_or(0),
        )),
        // GlobalNumByteSlice
        53 => Ok(TealValue::Uint(
            txn.global_state_schema
                .as_ref()
                .map(|s| s.num_byte_slice)
                .unwrap_or(0),
        )),
        // LocalNumUint
        54 => Ok(TealValue::Uint(
            txn.local_state_schema
                .as_ref()
                .map(|s| s.num_uint)
                .unwrap_or(0),
        )),
        // LocalNumByteSlice
        55 => Ok(TealValue::Uint(
            txn.local_state_schema
                .as_ref()
                .map(|s| s.num_byte_slice)
                .unwrap_or(0),
        )),
        // ExtraProgramPages
        56 => Ok(TealValue::Uint(txn.extra_program_pages as u64)),
        // Nonparticipation
        57 => Ok(TealValue::Uint(txn.non_participation as u64)),
        // Logs (array) — requires ApplyData; return empty in base implementation.
        // Callers with eval delta access should override txn_field for these.
        58 => match array_index {
            Some(i) => Err(AlgoError::Avm {
                message: format!("Logs index {} out of range (len=0)", i),
            }),
            None => Ok(TealValue::Uint(0)),
        },
        // NumLogs
        59 => Ok(TealValue::Uint(0)),
        // CreatedAssetID (from ApplyData)
        60 => Ok(TealValue::Uint(stxn.apply_data_config_asset)),
        // CreatedApplicationID (from ApplyData)
        61 => Ok(TealValue::Uint(stxn.apply_data_application_id)),
        // LastLog — requires ApplyData; return empty bytes in base implementation.
        62 => Ok(TealValue::Bytes(Vec::new())),
        // StateProofPK
        63 => Ok(TealValue::Bytes(
            txn.state_proof_pk
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ApprovalProgramPages (array)
        64 => {
            let program = txn
                .approval_program
                .as_ref()
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            let page_count = program.len().div_ceil(MAX_STRING_SIZE);
            match array_index {
                Some(i) => {
                    if i >= page_count {
                        Err(AlgoError::Avm {
                            message: format!("invalid ApprovalProgramPages index {i}"),
                        })
                    } else {
                        let first = i * MAX_STRING_SIZE;
                        let last = (first + MAX_STRING_SIZE).min(program.len());
                        Ok(TealValue::Bytes(program[first..last].to_vec()))
                    }
                }
                None => Ok(TealValue::Uint(page_count as u64)),
            }
        }
        // NumApprovalProgramPages
        65 => {
            let len = txn.approval_program.as_ref().map(|b| b.len()).unwrap_or(0);
            Ok(TealValue::Uint(len.div_ceil(MAX_STRING_SIZE) as u64))
        }
        // ClearStateProgramPages (array)
        66 => {
            let program = txn
                .clear_state_program
                .as_ref()
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            let page_count = program.len().div_ceil(MAX_STRING_SIZE);
            match array_index {
                Some(i) => {
                    if i >= page_count {
                        Err(AlgoError::Avm {
                            message: format!("invalid ClearStateProgramPages index {i}"),
                        })
                    } else {
                        let first = i * MAX_STRING_SIZE;
                        let last = (first + MAX_STRING_SIZE).min(program.len());
                        Ok(TealValue::Bytes(program[first..last].to_vec()))
                    }
                }
                None => Ok(TealValue::Uint(page_count as u64)),
            }
        }
        // NumClearStateProgramPages
        67 => {
            let len = txn
                .clear_state_program
                .as_ref()
                .map(|b| b.len())
                .unwrap_or(0);
            Ok(TealValue::Uint(len.div_ceil(MAX_STRING_SIZE) as u64))
        }
        // RejectVersion — AVM v12+.
        68 => Ok(TealValue::Uint(txn.reject_version)),
        _ => Err(AlgoError::Avm {
            message: format!("unknown TxnField index: {field}"),
        }),
    }
}
