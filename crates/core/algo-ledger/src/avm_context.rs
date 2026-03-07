//! `AvmContext` implementation backed by `LedgerStore`.
//!
//! `LedgerAvmContext` wraps a ledger store together with the current
//! transaction group, round metadata, and scratch/inner-txn state so that
//! the AVM can read/write chain state through the `AvmContext` trait defined
//! in `algo-avm`.

use std::collections::BTreeMap;

use algo_avm::context::AvmContext;
use algo_avm::MAX_AVM_VERSION;
use algo_error::AlgoError;
use algo_types::{Address, SignedTransaction, TealValue, Transaction};
use sha2::{Digest, Sha512_256};

use crate::params;
use crate::store_trait::LedgerStore;

/// Maximum byte string length in the AVM (matches go-algorand `maxStringSize`).
/// Used for program page chunking.
const MAX_STRING_SIZE: usize = 4096;

/// Integer division rounding up: `DivCeil(n, d)`.
fn div_ceil(n: usize, d: usize) -> usize {
    n.div_ceil(d)
}

// ---------------------------------------------------------------------------
// Helper: transaction type string -> TypeEnum integer
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helper: compute application address = SHA512/256("appID" || app_id_be_bytes)
// ---------------------------------------------------------------------------

fn app_address(app_id: u64) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"appID");
    h.update(app_id.to_be_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Helper: extract logs from a SignedTransaction's eval_delta
// ---------------------------------------------------------------------------

/// Extract log entries from a `SignedTransaction`'s `eval_delta` (the `dt` field).
/// Returns an empty vec if there is no eval_delta or no logs.
fn extract_logs_from_eval_delta(stxn: &SignedTransaction) -> Vec<Vec<u8>> {
    let Some(ref dt) = stxn.eval_delta else {
        return Vec::new();
    };
    match crate::eval_delta::parse_eval_delta(dt) {
        Ok(ed) => ed.logs.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// InnerTxnBuilder — accumulates fields for an itxn being built
// ---------------------------------------------------------------------------

/// Field indices that are array-valued and should accumulate across
/// multiple `itxn_field` calls rather than being overwritten.
const ARRAY_FIELD_INDICES: &[u8] = &[
    25, // ApplicationArgs
    27, // Accounts
    47, // Assets (foreign assets)
    49, // Applications (foreign apps)
];

/// Accumulates field values while an inner transaction is being constructed
/// via `itxn_begin` / `itxn_field` / `itxn_submit`.
#[derive(Debug, Clone, Default)]
struct InnerTxnBuilder {
    /// Scalar fields — latest `itxn_field` wins.
    fields: BTreeMap<u8, TealValue>,
    /// Array fields — each `itxn_field` appends to the list.
    array_fields: BTreeMap<u8, Vec<TealValue>>,
}

impl InnerTxnBuilder {
    fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
            array_fields: BTreeMap::new(),
        }
    }

    /// Set a field value. Array-valued fields accumulate; scalar fields
    /// are overwritten by the latest call.
    fn set_field(&mut self, field: u8, value: TealValue) {
        if ARRAY_FIELD_INDICES.contains(&field) {
            self.array_fields.entry(field).or_default().push(value);
        } else {
            self.fields.insert(field, value);
        }
    }

    /// Convert the accumulated fields into a minimal `SignedTransaction`.
    ///
    /// This performs a best-effort mapping from field bytes back into the
    /// flat Transaction struct. Full execution of inner transactions is
    /// deferred to Epic 22; for now we just store the built txn so that
    /// `last_itxn_field` can read it back.
    fn build(&self) -> SignedTransaction {
        let mut txn = Transaction::default();

        for (&field, value) in &self.fields {
            match field {
                // Sender
                0 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.sender = Address(addr);
                        }
                    }
                }
                // Fee
                1 => {
                    if let TealValue::Uint(v) = value {
                        txn.fee = *v;
                    }
                }
                // Receiver
                6 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.receiver = Address(addr);
                        }
                    }
                }
                // Amount
                7 => {
                    if let TealValue::Uint(v) = value {
                        txn.amount = *v;
                    }
                }
                // CloseRemainderTo
                8 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.close_remainder_to = Address(addr);
                        }
                    }
                }
                // Type (string)
                14 => {
                    if let TealValue::Bytes(b) = value {
                        txn.txn_type = String::from_utf8_lossy(b).to_string();
                    }
                }
                // TypeEnum
                15 => {
                    if let TealValue::Uint(v) = value {
                        txn.txn_type = match v {
                            1 => "pay",
                            2 => "keyreg",
                            3 => "acfg",
                            4 => "axfer",
                            5 => "afrz",
                            6 => "appl",
                            7 => "stpf",
                            _ => "",
                        }
                        .to_string();
                    }
                }
                // XferAsset
                16 => {
                    if let TealValue::Uint(v) = value {
                        txn.xaid = *v;
                    }
                }
                // AssetAmount
                17 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_amount = *v;
                    }
                }
                // AssetReceiver
                19 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_receiver = Some(Address(addr));
                        }
                    }
                }
                // AssetCloseTo
                20 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_close_to = Some(Address(addr));
                        }
                    }
                }
                // ApplicationID
                23 => {
                    if let TealValue::Uint(v) = value {
                        txn.application_id = *v;
                    }
                }
                // OnCompletion
                24 => {
                    if let TealValue::Uint(v) = value {
                        txn.on_completion = *v;
                    }
                }
                // ConfigAsset
                32 => {
                    if let TealValue::Uint(v) = value {
                        txn.config_asset = *v;
                    }
                }
                // FreezeAsset
                44 => {
                    if let TealValue::Uint(v) = value {
                        txn.freeze_asset = *v;
                    }
                }
                // FreezeAssetAccount
                45 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.freeze_account = Some(Address(addr));
                        }
                    }
                }
                // FreezeAssetFrozen
                46 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_frozen = *v != 0;
                    }
                }
                // Nonparticipation
                56 => {
                    if let TealValue::Uint(v) = value {
                        txn.non_participation = *v != 0;
                    }
                }
                _ => {
                    // Silently ignore unknown fields for forward-compatibility
                }
            }
        }

        // Process array fields.
        for (&field, values) in &self.array_fields {
            match field {
                // ApplicationArgs
                25 => {
                    let args: Vec<Option<serde_bytes::ByteBuf>> = values
                        .iter()
                        .map(|v| match v {
                            TealValue::Bytes(b) => Some(serde_bytes::ByteBuf::from(b.clone())),
                            TealValue::Uint(n) => {
                                Some(serde_bytes::ByteBuf::from(n.to_be_bytes().to_vec()))
                            }
                        })
                        .collect();
                    if !args.is_empty() {
                        txn.app_arguments = Some(args);
                    }
                }
                // Accounts
                27 => {
                    let accts: Vec<Address> = values
                        .iter()
                        .filter_map(|v| {
                            if let TealValue::Bytes(b) = v {
                                if b.len() == 32 {
                                    let mut addr = [0u8; 32];
                                    addr.copy_from_slice(b);
                                    return Some(Address(addr));
                                }
                            }
                            None
                        })
                        .collect();
                    if !accts.is_empty() {
                        txn.accounts = Some(accts);
                    }
                }
                // Assets (foreign assets)
                47 => {
                    let assets: Vec<u64> = values
                        .iter()
                        .filter_map(|v| {
                            if let TealValue::Uint(id) = v {
                                Some(*id)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !assets.is_empty() {
                        txn.foreign_assets = Some(assets);
                    }
                }
                // Applications (foreign apps)
                49 => {
                    let apps: Vec<u64> = values
                        .iter()
                        .filter_map(|v| {
                            if let TealValue::Uint(id) = v {
                                Some(*id)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !apps.is_empty() {
                        txn.foreign_apps = Some(apps);
                    }
                }
                _ => {}
            }
        }

        SignedTransaction {
            txn,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// LedgerAvmContext
// ---------------------------------------------------------------------------

/// AVM execution context backed by a `LedgerStore`.
///
/// Wraps ledger state, the current transaction group, and execution metadata
/// so that the AVM stack machine can access external state through the
/// `AvmContext` trait.
pub struct LedgerAvmContext<'a, L: LedgerStore> {
    /// The ledger store for account/asset/app queries.
    pub store: &'a mut L,
    /// The transaction group (all txns in the atomic group).
    pub group: Vec<SignedTransaction>,
    /// Index of the current transaction in the group.
    pub group_index: usize,
    /// Current round number.
    pub round: u64,
    /// Latest confirmed timestamp.
    pub latest_timestamp: u64,
    /// Current app ID (for app calls).
    pub app_id: u64,
    /// Creator address of the current app.
    pub creator: [u8; 32],
    /// LogicSig arguments (empty for app mode).
    pub lsig_args: Vec<Vec<u8>>,
    /// Whether running in app mode (`true`) or LogicSig mode (`false`).
    pub app_mode: bool,
    /// SHA-512/256 hash of the program bytes (for ed25519verify).
    pub program_hash_value: [u8; 32],
    /// Log entries collected during execution.
    pub logs: Vec<Vec<u8>>,
    /// Group scratch space: `scratch[group_index][slot]`.
    pub scratch: Vec<[TealValue; 256]>,
    /// Inner transaction currently being built (if any).
    inner_building: Vec<InnerTxnBuilder>,
    /// Completed inner transaction groups.
    inner_txns: Vec<Vec<SignedTransaction>>,
    /// Genesis hash.
    pub genesis_hash: [u8; 32],
}

// Helper to create a default scratch row (256 zero-uint slots).
fn default_scratch_row() -> [TealValue; 256] {
    std::array::from_fn(|_| TealValue::Uint(0))
}

impl<'a, L: LedgerStore> LedgerAvmContext<'a, L> {
    /// Create a new context. `scratch` is initialized to the right number of
    /// zero-filled rows for the group.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: &'a mut L,
        group: Vec<SignedTransaction>,
        group_index: usize,
        round: u64,
        latest_timestamp: u64,
        app_id: u64,
        creator: [u8; 32],
        app_mode: bool,
        program_hash: [u8; 32],
        genesis_hash: [u8; 32],
    ) -> Self {
        let group_len = group.len();
        Self {
            store,
            group,
            group_index,
            round,
            latest_timestamp,
            app_id,
            creator,
            lsig_args: Vec::new(),
            app_mode,
            program_hash_value: program_hash,
            logs: Vec::new(),
            scratch: (0..group_len).map(|_| default_scratch_row()).collect(),
            inner_building: Vec::new(),
            inner_txns: Vec::new(),
            genesis_hash,
        }
    }

    /// Set LogicSig arguments (for LogicSig mode).
    pub fn set_lsig_args(&mut self, args: Vec<Vec<u8>>) {
        self.lsig_args = args;
    }

    /// Get the current transaction in the group.
    fn current_txn(&self) -> &SignedTransaction {
        &self.group[self.group_index]
    }

    /// Collected log entries.
    pub fn logs(&self) -> &[Vec<u8>] {
        &self.logs
    }

    /// Completed inner transaction groups.
    pub fn inner_txns(&self) -> &[Vec<SignedTransaction>] {
        &self.inner_txns
    }
}

// ---------------------------------------------------------------------------
// Helpers for reading transaction fields
// ---------------------------------------------------------------------------

/// Read a transaction field from a `SignedTransaction`.
///
/// This is a standalone function so it can be used for both outer txn field
/// reads (`txn_field`) and inner txn field reads (`last_itxn_field`).
fn read_txn_field(
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
        // LastValid
        3 => Ok(TealValue::Uint(txn.last_valid.0)),
        // Note
        4 => Ok(TealValue::Bytes(txn.note.to_vec())),
        // Lease
        5 => Ok(TealValue::Bytes(txn.lease.to_vec())),
        // Receiver
        6 => Ok(TealValue::Bytes(txn.receiver.0.to_vec())),
        // Amount
        7 => Ok(TealValue::Uint(txn.amount)),
        // CloseRemainderTo
        8 => Ok(TealValue::Bytes(txn.close_remainder_to.0.to_vec())),
        // VotePK
        9 => Ok(TealValue::Bytes(
            txn.vote_pk.as_ref().map(|b| b.to_vec()).unwrap_or_default(),
        )),
        // SelectionPK
        10 => Ok(TealValue::Bytes(
            txn.selection_pk
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // VoteFirst
        11 => Ok(TealValue::Uint(txn.vote_first)),
        // VoteLast
        12 => Ok(TealValue::Uint(txn.vote_last)),
        // VoteKeyDilution
        13 => Ok(TealValue::Uint(txn.vote_key_dilution)),
        // Type
        14 => Ok(TealValue::Bytes(txn.txn_type.as_bytes().to_vec())),
        // TypeEnum
        15 => Ok(TealValue::Uint(type_enum(&txn.txn_type))),
        // XferAsset
        16 => Ok(TealValue::Uint(txn.xaid)),
        // AssetAmount
        17 => Ok(TealValue::Uint(txn.asset_amount)),
        // AssetSender
        18 => Ok(TealValue::Bytes(
            txn.asset_sender
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // AssetReceiver
        19 => Ok(TealValue::Bytes(
            txn.asset_receiver
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // AssetCloseTo
        20 => Ok(TealValue::Bytes(
            txn.asset_close_to
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // GroupIndex
        21 => Ok(TealValue::Uint(group_index_val as u64)),
        // TxID
        22 => {
            // TxID = SHA512/256("TX" || canonical_encode(txn))
            let digest = algo_codec::compute_txn_id(txn);
            Ok(TealValue::Bytes(digest.0.to_vec()))
        }
        // ApplicationID
        23 => Ok(TealValue::Uint(txn.application_id)),
        // OnCompletion
        24 => Ok(TealValue::Uint(txn.on_completion)),
        // ApplicationArgs (array)
        25 => {
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
        26 => {
            let args = txn.app_arguments.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(args.len() as u64))
        }
        // Accounts (array) — index 0 = sender, 1+ = accounts[i-1]
        // Per go-algorand: Accounts[0] is the sender, foreign accounts start at 1.
        // NumAccounts (when array_index is None) = len(apat), not including sender.
        27 => {
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
        28 => {
            let accts = txn.accounts.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(accts.len() as u64))
        }
        // ApprovalProgram
        29 => Ok(TealValue::Bytes(
            txn.approval_program
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ClearStateProgram
        30 => Ok(TealValue::Bytes(
            txn.clear_state_program
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // RekeyTo
        31 => Ok(TealValue::Bytes(
            txn.rekey_to
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAsset
        32 => Ok(TealValue::Uint(txn.config_asset)),
        // ConfigAssetTotal
        33 => Ok(TealValue::Uint(
            txn.asset_params.as_ref().map(|p| p.total).unwrap_or(0),
        )),
        // ConfigAssetDecimals
        34 => Ok(TealValue::Uint(
            txn.asset_params
                .as_ref()
                .map(|p| p.decimals as u64)
                .unwrap_or(0),
        )),
        // ConfigAssetDefaultFrozen
        35 => Ok(TealValue::Uint(
            txn.asset_params
                .as_ref()
                .map(|p| p.default_frozen as u64)
                .unwrap_or(0),
        )),
        // ConfigAssetUnitName
        36 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.unit_name.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetName
        37 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.asset_name.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetURL
        38 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .map(|p| p.url.as_bytes().to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetMetadataHash
        39 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.metadata_hash.as_ref())
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ConfigAssetManager
        40 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.manager.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetReserve
        41 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.reserve.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetFreeze
        42 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.freeze.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // ConfigAssetClawback
        43 => Ok(TealValue::Bytes(
            txn.asset_params
                .as_ref()
                .and_then(|p| p.clawback.as_ref())
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // FreezeAsset
        44 => Ok(TealValue::Uint(txn.freeze_asset)),
        // FreezeAssetAccount
        45 => Ok(TealValue::Bytes(
            txn.freeze_account
                .as_ref()
                .map(|a| a.0.to_vec())
                .unwrap_or_else(|| vec![0u8; 32]),
        )),
        // FreezeAssetFrozen
        46 => Ok(TealValue::Uint(txn.asset_frozen as u64)),
        // Assets (foreign assets array)
        47 => {
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
        48 => {
            let assets = txn.foreign_assets.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(assets.len() as u64))
        }
        // Applications (foreign apps array) — index 0 = current app ID, 1+ = foreign_apps[i-1]
        // Per go-algorand: Applications[0] is the current ApplicationID.
        // NumApplications (when array_index is None) = len(apfa), not including current app.
        49 => {
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
        50 => {
            let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
            Ok(TealValue::Uint(apps.len() as u64))
        }
        // GlobalNumUint
        51 => Ok(TealValue::Uint(
            txn.global_state_schema
                .as_ref()
                .map(|s| s.num_uint)
                .unwrap_or(0),
        )),
        // GlobalNumByteSlice
        52 => Ok(TealValue::Uint(
            txn.global_state_schema
                .as_ref()
                .map(|s| s.num_byte_slice)
                .unwrap_or(0),
        )),
        // LocalNumUint
        53 => Ok(TealValue::Uint(
            txn.local_state_schema
                .as_ref()
                .map(|s| s.num_uint)
                .unwrap_or(0),
        )),
        // LocalNumByteSlice
        54 => Ok(TealValue::Uint(
            txn.local_state_schema
                .as_ref()
                .map(|s| s.num_byte_slice)
                .unwrap_or(0),
        )),
        // ExtraProgramPages
        55 => Ok(TealValue::Uint(txn.extra_program_pages as u64)),
        // Nonparticipation
        56 => Ok(TealValue::Uint(txn.non_participation as u64)),
        // Logs (array) — extracted from ApplyData eval_delta ("dt.lg").
        57 => {
            let logs = extract_logs_from_eval_delta(stxn);
            match array_index {
                Some(i) => {
                    if i >= logs.len() {
                        Err(AlgoError::Avm {
                            message: format!("Logs index {} out of range (len={})", i, logs.len()),
                        })
                    } else {
                        Ok(TealValue::Bytes(logs[i].clone()))
                    }
                }
                None => Ok(TealValue::Uint(logs.len() as u64)),
            }
        }
        // NumLogs
        58 => {
            let logs = extract_logs_from_eval_delta(stxn);
            Ok(TealValue::Uint(logs.len() as u64))
        }
        // CreatedAssetID (from ApplyData)
        59 => Ok(TealValue::Uint(stxn.apply_data_config_asset)),
        // CreatedApplicationID (from ApplyData)
        60 => Ok(TealValue::Uint(stxn.apply_data_application_id)),
        // LastLog — the last entry in the eval_delta logs, or empty bytes.
        61 => {
            let logs = extract_logs_from_eval_delta(stxn);
            let last = logs.last().cloned().unwrap_or_default();
            Ok(TealValue::Bytes(last))
        }
        // StateProofPK
        62 => Ok(TealValue::Bytes(
            txn.state_proof_pk
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ApprovalProgramPages (array) — per go-algorand, pages are 4096-byte chunks.
        // maxStringSize = 4096; page_count = DivCeil(len, 4096); OOB index is an error.
        63 => {
            let program = txn
                .approval_program
                .as_ref()
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            let page_count = div_ceil(program.len(), MAX_STRING_SIZE);
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
        64 => {
            let len = txn.approval_program.as_ref().map(|b| b.len()).unwrap_or(0);
            Ok(TealValue::Uint(div_ceil(len, MAX_STRING_SIZE) as u64))
        }
        // ClearStateProgramPages (array) — same 4096-byte paging as approval.
        65 => {
            let program = txn
                .clear_state_program
                .as_ref()
                .map(|b| b.as_slice())
                .unwrap_or(&[]);
            let page_count = div_ceil(program.len(), MAX_STRING_SIZE);
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
        66 => {
            let len = txn
                .clear_state_program
                .as_ref()
                .map(|b| b.len())
                .unwrap_or(0);
            Ok(TealValue::Uint(div_ceil(len, MAX_STRING_SIZE) as u64))
        }
        _ => Err(AlgoError::Avm {
            message: format!("unknown TxnField index: {field}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// AvmContext implementation
// ---------------------------------------------------------------------------

impl<'a, L: LedgerStore> AvmContext for LedgerAvmContext<'a, L> {
    // ---- Transaction access ----

    fn txn_field(
        &self,
        group_index: usize,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        if group_index >= self.group.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "group_index {} out of range (group size={})",
                    group_index,
                    self.group.len()
                ),
            });
        }
        let stxn = &self.group[group_index];
        read_txn_field(stxn, field, array_index, group_index)
    }

    fn group_size(&self) -> usize {
        self.group.len()
    }

    fn group_index(&self) -> usize {
        self.group_index
    }

    // ---- Global fields ----

    fn global_field(&self, field: u8) -> Result<TealValue, AlgoError> {
        match field {
            // MinTxnFee
            0 => Ok(TealValue::Uint(1000)),
            // MinBalance
            1 => Ok(TealValue::Uint(params::MIN_BALANCE)),
            // MaxTxnLife
            2 => Ok(TealValue::Uint(1000)),
            // ZeroAddress
            3 => Ok(TealValue::Bytes(vec![0u8; 32])),
            // GroupSize
            4 => Ok(TealValue::Uint(self.group.len() as u64)),
            // LogicSigVersion
            5 => Ok(TealValue::Uint(MAX_AVM_VERSION as u64)),
            // Round
            6 => Ok(TealValue::Uint(self.round)),
            // LatestTimestamp
            7 => Ok(TealValue::Uint(self.latest_timestamp)),
            // CurrentApplicationID
            8 => Ok(TealValue::Uint(self.app_id)),
            // CreatorAddress
            9 => Ok(TealValue::Bytes(self.creator.to_vec())),
            // CurrentApplicationAddress
            10 => Ok(TealValue::Bytes(app_address(self.app_id).to_vec())),
            // GroupID
            11 => {
                let group_id = if !self.group.is_empty() {
                    let g = &self.group[0].txn.group;
                    if g.is_empty() {
                        vec![0u8; 32]
                    } else {
                        g.to_vec()
                    }
                } else {
                    vec![0u8; 32]
                };
                Ok(TealValue::Bytes(group_id))
            }
            // OpcodeBudget — handled directly in op_global (reads machine.budget);
            // this fallback returns 0 but should not normally be reached.
            12 => Ok(TealValue::Uint(0)),
            // CallerApplicationID — 0 when not called from another app
            13 => Ok(TealValue::Uint(0)),
            // CallerApplicationAddress — zero address when no caller
            14 => Ok(TealValue::Bytes(vec![0u8; 32])),
            // AssetCreateMinBalance
            15 => Ok(TealValue::Uint(params::ASSET_OPT_IN_MIN_BALANCE)),
            // AssetOptInMinBalance
            16 => Ok(TealValue::Uint(params::ASSET_OPT_IN_MIN_BALANCE)),
            // GenesisHash
            17 => Ok(TealValue::Bytes(self.genesis_hash.to_vec())),
            // PayoutsEnabled .. PayoutsMaxBalance (18-22) — default to 0
            18..=22 => Ok(TealValue::Uint(0)),
            _ => Err(AlgoError::Avm {
                message: format!("unknown GlobalField index: {field}"),
            }),
        }
    }

    // ---- LogicSig arguments ----

    fn arg(&self, index: usize) -> Result<Vec<u8>, AlgoError> {
        self.lsig_args
            .get(index)
            .cloned()
            .ok_or_else(|| AlgoError::Avm {
                message: format!(
                    "arg index {} out of range (num_args={})",
                    index,
                    self.lsig_args.len()
                ),
            })
    }

    fn num_args(&self) -> usize {
        self.lsig_args.len()
    }

    // ---- Account / asset / app reference resolution ----

    fn resolve_account(&self, index: u64) -> Result<[u8; 32], AlgoError> {
        let txn = &self.current_txn().txn;
        if index == 0 {
            return Ok(txn.sender.0);
        }
        let accounts = txn.accounts.as_deref().unwrap_or(&[]);
        let i = (index - 1) as usize;
        if i < accounts.len() {
            Ok(accounts[i].0)
        } else {
            Err(AlgoError::Avm {
                message: format!(
                    "resolve_account: index {} out of range (accounts len={})",
                    index,
                    accounts.len() + 1
                ),
            })
        }
    }

    fn resolve_asset(&self, index: u64) -> Result<u64, AlgoError> {
        let txn = &self.current_txn().txn;
        if index == 0 {
            // Index 0 = the "implied" asset: xfer_asset, config_asset, or freeze_asset
            let id = if txn.xaid != 0 {
                txn.xaid
            } else if txn.config_asset != 0 {
                txn.config_asset
            } else {
                txn.freeze_asset
            };
            if id == 0 {
                return Err(AlgoError::Avm {
                    message: "resolve_asset: index 0 but no implied asset".to_string(),
                });
            }
            return Ok(id);
        }
        let assets = txn.foreign_assets.as_deref().unwrap_or(&[]);
        let i = (index - 1) as usize;
        if i < assets.len() {
            Ok(assets[i])
        } else {
            Err(AlgoError::Avm {
                message: format!(
                    "resolve_asset: index {} out of range (foreign_assets len={})",
                    index,
                    assets.len() + 1
                ),
            })
        }
    }

    fn resolve_app(&self, index: u64) -> Result<u64, AlgoError> {
        if index == 0 {
            return Ok(self.app_id);
        }
        let txn = &self.current_txn().txn;
        let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
        let i = (index - 1) as usize;
        if i < apps.len() {
            Ok(apps[i])
        } else {
            Err(AlgoError::Avm {
                message: format!(
                    "resolve_app: index {} out of range (foreign_apps len={})",
                    index,
                    apps.len() + 1
                ),
            })
        }
    }

    // ---- State reads ----

    fn app_opted_in(&self, account: &[u8; 32], app_id: u64) -> Result<bool, AlgoError> {
        let addr = Address(*account);
        Ok(self.store.has_app_local_state(&addr, app_id))
    }

    fn app_local_get(
        &self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<Option<TealValue>, AlgoError> {
        let addr = Address(*account);
        match self.store.get_app_local_state(&addr, app_id) {
            Some(local) => Ok(local.key_value.get(key).cloned()),
            None => Ok(None),
        }
    }

    fn app_global_get(&self, app_id: u64, key: &[u8]) -> Result<Option<TealValue>, AlgoError> {
        match self.store.get_app_params(app_id) {
            Some(params) => Ok(params.global_state.get(key).cloned()),
            None => Ok(None),
        }
    }

    // ---- State writes ----

    fn app_local_put(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        let addr = Address(*account);
        let mut local = self
            .store
            .get_app_local_state(&addr, app_id)
            .ok_or_else(|| AlgoError::Avm {
                message: format!(
                    "app_local_put: account {} not opted in to app {app_id}",
                    Address(*account)
                ),
            })?;
        local.key_value.insert(key.to_vec(), value);
        self.store.set_app_local_state(&addr, app_id, local);
        Ok(())
    }

    fn app_local_del(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<(), AlgoError> {
        let addr = Address(*account);
        if let Some(mut local) = self.store.get_app_local_state(&addr, app_id) {
            local.key_value.remove(key);
            self.store.set_app_local_state(&addr, app_id, local);
        }
        Ok(())
    }

    fn app_global_put(
        &mut self,
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        let mut p = self
            .store
            .get_app_params(app_id)
            .ok_or_else(|| AlgoError::Avm {
                message: format!("app_global_put: app {app_id} not found"),
            })?;
        p.global_state.insert(key.to_vec(), value);
        self.store.set_app_params(app_id, p);
        Ok(())
    }

    fn app_global_del(&mut self, app_id: u64, key: &[u8]) -> Result<(), AlgoError> {
        if let Some(mut p) = self.store.get_app_params(app_id) {
            p.global_state.remove(key);
            self.store.set_app_params(app_id, p);
        }
        Ok(())
    }

    // ---- Account / asset / app parameter queries ----

    fn balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        let addr = Address(*account);
        Ok(self
            .store
            .get_account(&addr)
            .map(|a| a.micro_algos)
            .unwrap_or(0))
    }

    fn min_balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        let addr = Address(*account);
        let acct = self.store.get_or_default_account(&addr);
        Ok(self.store.min_balance_with_state(&addr, &acct))
    }

    fn asset_holding_get(
        &self,
        account: &[u8; 32],
        asset_id: u64,
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        let addr = Address(*account);
        match self.store.get_asset_holding(&addr, asset_id) {
            Some(holding) => {
                let val = match field {
                    // AssetBalance
                    0 => TealValue::Uint(holding.amount),
                    // AssetFrozen
                    1 => TealValue::Uint(holding.frozen as u64),
                    _ => {
                        return Err(AlgoError::Avm {
                            message: format!("unknown AssetHoldingField index: {field}"),
                        })
                    }
                };
                Ok((val, true))
            }
            None => Ok((TealValue::Uint(0), false)),
        }
    }

    fn asset_params_get(&self, asset_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        match self.store.get_asset_params(asset_id) {
            Some(record) => {
                let p = &record.params;
                let val = match field {
                    // AssetTotal
                    0 => TealValue::Uint(p.total),
                    // AssetDecimals
                    1 => TealValue::Uint(p.decimals as u64),
                    // AssetDefaultFrozen
                    2 => TealValue::Uint(p.default_frozen as u64),
                    // AssetUnitName
                    3 => TealValue::Bytes(p.unit_name.as_bytes().to_vec()),
                    // AssetName
                    4 => TealValue::Bytes(p.asset_name.as_bytes().to_vec()),
                    // AssetURL
                    5 => TealValue::Bytes(p.url.as_bytes().to_vec()),
                    // AssetMetadataHash
                    6 => TealValue::Bytes(
                        p.metadata_hash
                            .as_ref()
                            .map(|b| b.to_vec())
                            .unwrap_or_default(),
                    ),
                    // AssetManager
                    7 => TealValue::Bytes(
                        p.manager
                            .as_ref()
                            .map(|a| a.0.to_vec())
                            .unwrap_or_else(|| vec![0u8; 32]),
                    ),
                    // AssetReserve
                    8 => TealValue::Bytes(
                        p.reserve
                            .as_ref()
                            .map(|a| a.0.to_vec())
                            .unwrap_or_else(|| vec![0u8; 32]),
                    ),
                    // AssetFreeze
                    9 => TealValue::Bytes(
                        p.freeze
                            .as_ref()
                            .map(|a| a.0.to_vec())
                            .unwrap_or_else(|| vec![0u8; 32]),
                    ),
                    // AssetClawback
                    10 => TealValue::Bytes(
                        p.clawback
                            .as_ref()
                            .map(|a| a.0.to_vec())
                            .unwrap_or_else(|| vec![0u8; 32]),
                    ),
                    // AssetCreator
                    11 => TealValue::Bytes(record.creator.0.to_vec()),
                    _ => {
                        return Err(AlgoError::Avm {
                            message: format!("unknown AssetParamsField index: {field}"),
                        })
                    }
                };
                Ok((val, true))
            }
            None => Ok((TealValue::Uint(0), false)),
        }
    }

    fn app_params_get(&self, app_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        match self.store.get_app_params(app_id) {
            Some(p) => {
                let val = match field {
                    // AppApprovalProgram
                    0 => TealValue::Bytes(p.approval_program.clone()),
                    // AppClearStateProgram
                    1 => TealValue::Bytes(p.clear_state_program.clone()),
                    // AppGlobalNumUint
                    2 => TealValue::Uint(p.global_state_schema.num_uint),
                    // AppGlobalNumByteSlice
                    3 => TealValue::Uint(p.global_state_schema.num_byte_slice),
                    // AppLocalNumUint
                    4 => TealValue::Uint(p.local_state_schema.num_uint),
                    // AppLocalNumByteSlice
                    5 => TealValue::Uint(p.local_state_schema.num_byte_slice),
                    // AppExtraProgramPages
                    6 => TealValue::Uint(p.extra_program_pages as u64),
                    // AppCreator
                    7 => TealValue::Bytes(p.creator.0.to_vec()),
                    // AppAddress
                    8 => TealValue::Bytes(app_address(app_id).to_vec()),
                    _ => {
                        return Err(AlgoError::Avm {
                            message: format!("unknown AppParamsField index: {field}"),
                        })
                    }
                };
                Ok((val, true))
            }
            None => Ok((TealValue::Uint(0), false)),
        }
    }

    fn acct_params_get(
        &self,
        account: &[u8; 32],
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        let addr = Address(*account);
        match self.store.get_account(&addr) {
            Some(acct) => {
                let val = match field {
                    // AcctBalance
                    0 => TealValue::Uint(acct.micro_algos),
                    // AcctMinBalance
                    1 => TealValue::Uint(self.store.min_balance_with_state(&addr, &acct)),
                    // AcctAuthAddr
                    2 => TealValue::Bytes(
                        acct.auth_addr
                            .as_ref()
                            .map(|a| a.0.to_vec())
                            .unwrap_or_else(|| vec![0u8; 32]),
                    ),
                    // AcctTotalNumUint
                    3 => TealValue::Uint(0), // requires per-app schema aggregation
                    // AcctTotalNumByteSlice
                    4 => TealValue::Uint(0), // requires per-app schema aggregation
                    // AcctTotalExtraAppPages
                    5 => TealValue::Uint(acct.total_extra_app_pages as u64),
                    // AcctTotalAppsCreated
                    6 => TealValue::Uint(acct.total_created_apps),
                    // AcctTotalAppsOptedIn
                    7 => TealValue::Uint(acct.total_apps_opted_in),
                    // AcctTotalAssetsCreated
                    8 => TealValue::Uint(acct.total_created_assets),
                    // AcctTotalAssets
                    9 => TealValue::Uint(acct.total_assets_opted_in),
                    // AcctTotalBoxes
                    10 => TealValue::Uint(acct.total_boxes),
                    // AcctTotalBoxBytes
                    11 => TealValue::Uint(acct.total_box_bytes),
                    // AcctIncentiveEligible
                    12 => TealValue::Uint(0), // not yet tracked
                    // AcctLastProposed
                    13 => TealValue::Uint(0), // not yet tracked
                    // AcctLastHeartbeat
                    14 => TealValue::Uint(0), // not yet tracked
                    _ => {
                        return Err(AlgoError::Avm {
                            message: format!("unknown AcctParamsField index: {field}"),
                        })
                    }
                };
                Ok((val, true))
            }
            None => Ok((TealValue::Uint(0), false)),
        }
    }

    // ---- Logging ----

    fn log(&mut self, data: Vec<u8>) -> Result<(), AlgoError> {
        self.logs.push(data);
        Ok(())
    }

    // ---- Group scratch space ----

    fn gload(&self, group_index: usize, slot: u8) -> Result<TealValue, AlgoError> {
        if group_index >= self.scratch.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "gload: group_index {} out of range (group size={})",
                    group_index,
                    self.scratch.len()
                ),
            });
        }
        Ok(self.scratch[group_index][slot as usize].clone())
    }

    // ---- Inner transactions ----

    fn itxn_begin(&mut self) -> Result<(), AlgoError> {
        // Per go-algorand, calling itxn_begin while already building discards
        // the in-progress group and starts fresh.
        self.inner_building.clear();
        self.inner_building.push(InnerTxnBuilder::new());
        Ok(())
    }

    fn itxn_field(&mut self, field: u8, value: TealValue) -> Result<(), AlgoError> {
        let builder = self
            .inner_building
            .last_mut()
            .ok_or_else(|| AlgoError::Avm {
                message: "itxn_field: no inner txn being built".to_string(),
            })?;
        builder.set_field(field, value);
        Ok(())
    }

    fn itxn_next(&mut self) -> Result<(), AlgoError> {
        if self.inner_building.is_empty() {
            return Err(AlgoError::Avm {
                message: "itxn_next: no inner txn being built".to_string(),
            });
        }
        self.inner_building.push(InnerTxnBuilder::new());
        Ok(())
    }

    fn itxn_submit(&mut self) -> Result<(), AlgoError> {
        if self.inner_building.is_empty() {
            return Err(AlgoError::Avm {
                message: "itxn_submit: no inner txn being built".to_string(),
            });
        }
        let builders = std::mem::take(&mut self.inner_building);
        let default_sender = Address(app_address(self.app_id));
        let txns: Vec<SignedTransaction> = builders
            .iter()
            .map(|b| {
                let mut stxn = b.build();
                if stxn.txn.sender == Address::ZERO {
                    stxn.txn.sender = default_sender;
                }
                stxn
            })
            .collect();
        self.inner_txns.push(txns);
        Ok(())
    }

    fn last_itxn_field(
        &self,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        let last_group = self.inner_txns.last().ok_or_else(|| AlgoError::Avm {
            message: "last_itxn_field: no inner txns submitted".to_string(),
        })?;
        let last_txn = last_group.last().ok_or_else(|| AlgoError::Avm {
            message: "last_itxn_field: empty inner txn group".to_string(),
        })?;
        read_txn_field(last_txn, field, array_index, 0)
    }

    fn last_itxn_group_field(
        &self,
        group_index: usize,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        let last_group = self.inner_txns.last().ok_or_else(|| AlgoError::Avm {
            message: "last_itxn_group_field: no inner txns submitted".to_string(),
        })?;
        if group_index >= last_group.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "last_itxn_group_field: index {} out of range (group size={})",
                    group_index,
                    last_group.len()
                ),
            });
        }
        read_txn_field(&last_group[group_index], field, array_index, group_index)
    }

    fn num_inner_txns(&self) -> usize {
        self.inner_txns.iter().map(|g| g.len()).sum()
    }

    // ---- Execution mode / identity ----

    fn is_app_mode(&self) -> bool {
        self.app_mode
    }

    fn current_app_id(&self) -> u64 {
        self.app_id
    }

    fn program_hash(&self) -> [u8; 32] {
        self.program_hash_value
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;
    use algo_types::{
        AccountData, AppLocalState, AppParams, AssetHolding as AssetHoldingType, AssetParamsRecord,
        StateSchema,
    };
    use std::collections::BTreeMap;

    /// Helper: build a simple payment transaction.
    fn make_pay_txn(sender: [u8; 32], receiver: [u8; 32], amount: u64) -> SignedTransaction {
        use serde_bytes::ByteBuf;
        SignedTransaction {
            txn: Transaction {
                txn_type: "pay".to_string(),
                sender: Address(sender),
                fee: 1000,
                first_valid: 100.into(),
                last_valid: 200.into(),
                receiver: Address(receiver),
                amount,
                note: ByteBuf::from(b"hello".to_vec()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Helper: build an appl transaction.
    fn make_appl_txn(
        sender: [u8; 32],
        app_id: u64,
        accounts: Vec<Address>,
        foreign_apps: Vec<u64>,
        foreign_assets: Vec<u64>,
    ) -> SignedTransaction {
        use serde_bytes::ByteBuf;
        SignedTransaction {
            txn: Transaction {
                txn_type: "appl".to_string(),
                sender: Address(sender),
                fee: 1000,
                first_valid: 100.into(),
                last_valid: 200.into(),
                application_id: app_id,
                on_completion: 0,
                accounts: if accounts.is_empty() {
                    None
                } else {
                    Some(accounts)
                },
                foreign_apps: if foreign_apps.is_empty() {
                    None
                } else {
                    Some(foreign_apps)
                },
                foreign_assets: if foreign_assets.is_empty() {
                    None
                } else {
                    Some(foreign_assets)
                },
                app_arguments: Some(vec![
                    Some(ByteBuf::from(b"arg0".to_vec())),
                    Some(ByteBuf::from(b"arg1".to_vec())),
                ]),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn make_context(
        store: &mut LedgerState,
        group: Vec<SignedTransaction>,
    ) -> LedgerAvmContext<'_, LedgerState> {
        LedgerAvmContext::new(
            store, group, 0,     // group_index
            1000,  // round
            12345, // latest_timestamp
            42,    // app_id
            [1u8; 32], true, // app_mode
            [2u8; 32], [3u8; 32],
        )
    }

    // ---- type_enum tests ----

    #[test]
    fn type_enum_mapping() {
        assert_eq!(type_enum("pay"), 1);
        assert_eq!(type_enum("keyreg"), 2);
        assert_eq!(type_enum("acfg"), 3);
        assert_eq!(type_enum("axfer"), 4);
        assert_eq!(type_enum("afrz"), 5);
        assert_eq!(type_enum("appl"), 6);
        assert_eq!(type_enum("stpf"), 7);
        assert_eq!(type_enum("unknown"), 0);
    }

    // ---- txn_field tests ----

    #[test]
    fn txn_field_sender() {
        let sender = [10u8; 32];
        let receiver = [20u8; 32];
        let txn = make_pay_txn(sender, receiver, 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let val = ctx.txn_field(0, 0, None).unwrap(); // Sender
        assert_eq!(val, TealValue::Bytes(sender.to_vec()));
    }

    #[test]
    fn txn_field_fee() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let val = ctx.txn_field(0, 1, None).unwrap(); // Fee
        assert_eq!(val, TealValue::Uint(1000));
    }

    #[test]
    fn txn_field_type_and_type_enum() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let type_val = ctx.txn_field(0, 14, None).unwrap(); // Type
        assert_eq!(type_val, TealValue::Bytes(b"pay".to_vec()));

        let type_enum_val = ctx.txn_field(0, 15, None).unwrap(); // TypeEnum
        assert_eq!(type_enum_val, TealValue::Uint(1));
    }

    #[test]
    fn txn_field_amount_receiver() {
        let sender = [10u8; 32];
        let receiver = [20u8; 32];
        let txn = make_pay_txn(sender, receiver, 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let amount = ctx.txn_field(0, 7, None).unwrap(); // Amount
        assert_eq!(amount, TealValue::Uint(5000));

        let rcv = ctx.txn_field(0, 6, None).unwrap(); // Receiver
        assert_eq!(rcv, TealValue::Bytes(receiver.to_vec()));
    }

    #[test]
    fn txn_field_first_last_valid() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let fv = ctx.txn_field(0, 2, None).unwrap(); // FirstValid
        assert_eq!(fv, TealValue::Uint(100));

        let lv = ctx.txn_field(0, 3, None).unwrap(); // LastValid
        assert_eq!(lv, TealValue::Uint(200));
    }

    #[test]
    fn txn_field_note() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let note = ctx.txn_field(0, 4, None).unwrap(); // Note
        assert_eq!(note, TealValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn txn_field_group_index() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let gi = ctx.txn_field(0, 21, None).unwrap(); // GroupIndex
        assert_eq!(gi, TealValue::Uint(0));
    }

    #[test]
    fn txn_field_out_of_range_group() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let result = ctx.txn_field(1, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn txn_field_application_args_array() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumAppArgs
        let num = ctx.txn_field(0, 26, None).unwrap();
        assert_eq!(num, TealValue::Uint(2));

        // ApplicationArgs[0]
        let arg0 = ctx.txn_field(0, 25, Some(0)).unwrap();
        assert_eq!(arg0, TealValue::Bytes(b"arg0".to_vec()));

        // ApplicationArgs[1]
        let arg1 = ctx.txn_field(0, 25, Some(1)).unwrap();
        assert_eq!(arg1, TealValue::Bytes(b"arg1".to_vec()));

        // Out-of-range
        assert!(ctx.txn_field(0, 25, Some(2)).is_err());
    }

    #[test]
    fn txn_field_accounts_array() {
        let sender = [10u8; 32];
        let acct1 = Address([30u8; 32]);
        let acct2 = Address([40u8; 32]);
        let txn = make_appl_txn(sender, 42, vec![acct1, acct2], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumAccounts = len(apat), not including sender
        let num = ctx.txn_field(0, 28, None).unwrap();
        assert_eq!(num, TealValue::Uint(2));

        // Accounts[0] = sender (per go-algorand semantics)
        let a0 = ctx.txn_field(0, 27, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Bytes(sender.to_vec()));

        // Accounts[1] = apat[0]
        let a1 = ctx.txn_field(0, 27, Some(1)).unwrap();
        assert_eq!(a1, TealValue::Bytes(acct1.0.to_vec()));

        // Accounts[2] = apat[1]
        let a2 = ctx.txn_field(0, 27, Some(2)).unwrap();
        assert_eq!(a2, TealValue::Bytes(acct2.0.to_vec()));

        // Accounts[3] = out of range
        assert!(ctx.txn_field(0, 27, Some(3)).is_err());
    }

    #[test]
    fn txn_field_foreign_assets_and_apps() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100, 200], vec![50, 60]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApplications = len(apfa), not including current app
        assert_eq!(ctx.txn_field(0, 50, None).unwrap(), TealValue::Uint(2));
        // Applications[0] = current ApplicationID (per go-algorand semantics)
        assert_eq!(ctx.txn_field(0, 49, Some(0)).unwrap(), TealValue::Uint(42));
        // Applications[1] = apfa[0]
        assert_eq!(ctx.txn_field(0, 49, Some(1)).unwrap(), TealValue::Uint(100));
        // Applications[2] = apfa[1]
        assert_eq!(ctx.txn_field(0, 49, Some(2)).unwrap(), TealValue::Uint(200));
        // Applications[3] = out of range
        assert!(ctx.txn_field(0, 49, Some(3)).is_err());

        // NumAssets (0-based, no special index 0)
        assert_eq!(ctx.txn_field(0, 48, None).unwrap(), TealValue::Uint(2));
        // Assets[0] = foreign_assets[0]
        assert_eq!(ctx.txn_field(0, 47, Some(0)).unwrap(), TealValue::Uint(50));
        // Assets[1] = foreign_assets[1]
        assert_eq!(ctx.txn_field(0, 47, Some(1)).unwrap(), TealValue::Uint(60));
        // Assets[2] = out of range
        assert!(ctx.txn_field(0, 47, Some(2)).is_err());
    }

    // ---- global_field tests ----

    #[test]
    fn global_field_min_txn_fee() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.global_field(0).unwrap(), TealValue::Uint(1000)); // MinTxnFee
    }

    #[test]
    fn global_field_round_and_timestamp() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.global_field(6).unwrap(), TealValue::Uint(1000)); // Round
        assert_eq!(ctx.global_field(7).unwrap(), TealValue::Uint(12345)); // LatestTimestamp
    }

    #[test]
    fn global_field_group_size() {
        let txn1 = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let txn2 = make_pay_txn([10u8; 32], [30u8; 32], 3000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn1, txn2]);

        assert_eq!(ctx.global_field(4).unwrap(), TealValue::Uint(2)); // GroupSize
    }

    #[test]
    fn global_field_current_app_id() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.global_field(8).unwrap(), TealValue::Uint(42)); // CurrentApplicationID
    }

    #[test]
    fn global_field_creator_address() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(
            ctx.global_field(9).unwrap(),
            TealValue::Bytes([1u8; 32].to_vec())
        ); // CreatorAddress
    }

    #[test]
    fn global_field_app_address() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let val = ctx.global_field(10).unwrap(); // CurrentApplicationAddress
        let expected = app_address(42);
        assert_eq!(val, TealValue::Bytes(expected.to_vec()));
    }

    #[test]
    fn global_field_zero_address() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(
            ctx.global_field(3).unwrap(),
            TealValue::Bytes(vec![0u8; 32])
        ); // ZeroAddress
    }

    #[test]
    fn global_field_genesis_hash() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(
            ctx.global_field(17).unwrap(),
            TealValue::Bytes([3u8; 32].to_vec())
        ); // GenesisHash
    }

    #[test]
    fn global_field_unknown() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.global_field(99).is_err());
    }

    // ---- resolve tests ----

    #[test]
    fn resolve_account_sender_and_accounts() {
        let sender = [10u8; 32];
        let acct1 = Address([30u8; 32]);
        let acct2 = Address([40u8; 32]);
        let txn = make_appl_txn(sender, 42, vec![acct1, acct2], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // Index 0 = sender
        assert_eq!(ctx.resolve_account(0).unwrap(), sender);
        // Index 1 = accounts[0]
        assert_eq!(ctx.resolve_account(1).unwrap(), acct1.0);
        // Index 2 = accounts[1]
        assert_eq!(ctx.resolve_account(2).unwrap(), acct2.0);
        // Out of range
        assert!(ctx.resolve_account(3).is_err());
    }

    #[test]
    fn resolve_asset_implied_and_foreign() {
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 42, vec![], vec![], vec![50, 60]);
        txn.txn.xaid = 99; // implied asset
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.resolve_asset(0).unwrap(), 99);
        assert_eq!(ctx.resolve_asset(1).unwrap(), 50);
        assert_eq!(ctx.resolve_asset(2).unwrap(), 60);
        assert!(ctx.resolve_asset(3).is_err());
    }

    #[test]
    fn resolve_app_current_and_foreign() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100, 200], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.resolve_app(0).unwrap(), 42); // current app
        assert_eq!(ctx.resolve_app(1).unwrap(), 100);
        assert_eq!(ctx.resolve_app(2).unwrap(), 200);
        assert!(ctx.resolve_app(3).is_err());
    }

    // ---- State read/write tests ----

    #[test]
    fn app_global_state_read_write() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Set up an app with global state
        let mut global = BTreeMap::new();
        global.insert(b"counter".to_vec(), TealValue::Uint(0));
        store.app_params.insert(
            42,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: vec![],
                clear_state_program: vec![],
                global_state: global,
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema {
                    num_uint: 1,
                    num_byte_slice: 0,
                },
                extra_program_pages: 0,
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);

        // Read existing key
        let val = ctx.app_global_get(42, b"counter").unwrap();
        assert_eq!(val, Some(TealValue::Uint(0)));

        // Write a new value
        ctx.app_global_put(42, b"counter", TealValue::Uint(5))
            .unwrap();
        let val = ctx.app_global_get(42, b"counter").unwrap();
        assert_eq!(val, Some(TealValue::Uint(5)));

        // Delete
        ctx.app_global_del(42, b"counter").unwrap();
        let val = ctx.app_global_get(42, b"counter").unwrap();
        assert_eq!(val, None);

        // Non-existent key
        let val = ctx.app_global_get(42, b"missing").unwrap();
        assert_eq!(val, None);

        // Non-existent app
        let val = ctx.app_global_get(999, b"counter").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn app_local_state_read_write() {
        let sender = [10u8; 32];
        let txn = make_pay_txn(sender, [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Opt in: create local state for sender in app 42
        let local = AppLocalState {
            schema: StateSchema {
                num_uint: 2,
                num_byte_slice: 0,
            },
            key_value: BTreeMap::new(),
        };
        store.app_local_states.insert((Address(sender), 42), local);

        let mut ctx = make_context(&mut store, vec![txn]);

        // opted_in
        assert!(ctx.app_opted_in(&sender, 42).unwrap());
        assert!(!ctx.app_opted_in(&sender, 99).unwrap());

        // Read empty
        assert_eq!(ctx.app_local_get(&sender, 42, b"x").unwrap(), None);

        // Write
        ctx.app_local_put(&sender, 42, b"x", TealValue::Uint(7))
            .unwrap();
        assert_eq!(
            ctx.app_local_get(&sender, 42, b"x").unwrap(),
            Some(TealValue::Uint(7))
        );

        // Delete
        ctx.app_local_del(&sender, 42, b"x").unwrap();
        assert_eq!(ctx.app_local_get(&sender, 42, b"x").unwrap(), None);

        // Write to non-opted-in app should fail
        let result = ctx.app_local_put(&sender, 99, b"x", TealValue::Uint(1));
        assert!(result.is_err());
    }

    // ---- balance/min_balance tests ----

    #[test]
    fn balance_and_min_balance() {
        let addr = [10u8; 32];
        let txn = make_pay_txn(addr, [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.accounts.insert(
            Address(addr),
            AccountData {
                micro_algos: 1_000_000,
                ..Default::default()
            },
        );

        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.balance(&addr).unwrap(), 1_000_000);
        assert_eq!(ctx.min_balance(&addr).unwrap(), params::MIN_BALANCE);
    }

    #[test]
    fn balance_nonexistent_account() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.balance(&[99u8; 32]).unwrap(), 0);
    }

    // ---- asset_holding_get / asset_params_get tests ----

    #[test]
    fn asset_holding_get_found() {
        let addr = [10u8; 32];
        let txn = make_pay_txn(addr, [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.asset_holdings.insert(
            (Address(addr), 7),
            AssetHoldingType {
                amount: 1000,
                frozen: true,
            },
        );

        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.asset_holding_get(&addr, 7, 0).unwrap(); // AssetBalance
        assert!(exists);
        assert_eq!(val, TealValue::Uint(1000));

        let (val, exists) = ctx.asset_holding_get(&addr, 7, 1).unwrap(); // AssetFrozen
        assert!(exists);
        assert_eq!(val, TealValue::Uint(1));
    }

    #[test]
    fn asset_holding_get_not_found() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.asset_holding_get(&[10u8; 32], 7, 0).unwrap();
        assert!(!exists);
        assert_eq!(val, TealValue::Uint(0));
    }

    #[test]
    fn asset_params_get_found() {
        use algo_types::AssetParams as TxnAssetParams;
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.asset_params.insert(
            7,
            AssetParamsRecord {
                params: TxnAssetParams {
                    total: 1_000_000,
                    decimals: 6,
                    unit_name: "ALGO".to_string(),
                    asset_name: "Algorand".to_string(),
                    ..Default::default()
                },
                creator: Address([50u8; 32]),
            },
        );

        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.asset_params_get(7, 0).unwrap(); // AssetTotal
        assert!(exists);
        assert_eq!(val, TealValue::Uint(1_000_000));

        let (val, _) = ctx.asset_params_get(7, 3).unwrap(); // AssetUnitName
        assert_eq!(val, TealValue::Bytes(b"ALGO".to_vec()));

        let (val, _) = ctx.asset_params_get(7, 11).unwrap(); // AssetCreator
        assert_eq!(val, TealValue::Bytes([50u8; 32].to_vec()));
    }

    // ---- app_params_get tests ----

    #[test]
    fn app_params_get_found() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.app_params.insert(
            42,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: vec![0x06, 0x81, 0x01],
                clear_state_program: vec![0x06, 0x81, 0x01],
                global_state: BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 1,
                },
                global_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 2,
                },
                extra_program_pages: 1,
            },
        );

        let ctx = make_context(&mut store, vec![txn]);

        // AppApprovalProgram
        let (val, exists) = ctx.app_params_get(42, 0).unwrap();
        assert!(exists);
        assert_eq!(val, TealValue::Bytes(vec![0x06, 0x81, 0x01]));

        // AppGlobalNumUint
        let (val, _) = ctx.app_params_get(42, 2).unwrap();
        assert_eq!(val, TealValue::Uint(4));

        // AppLocalNumByteSlice
        let (val, _) = ctx.app_params_get(42, 5).unwrap();
        assert_eq!(val, TealValue::Uint(1));

        // AppExtraProgramPages
        let (val, _) = ctx.app_params_get(42, 6).unwrap();
        assert_eq!(val, TealValue::Uint(1));

        // AppCreator
        let (val, _) = ctx.app_params_get(42, 7).unwrap();
        assert_eq!(val, TealValue::Bytes([1u8; 32].to_vec()));

        // AppAddress
        let (val, _) = ctx.app_params_get(42, 8).unwrap();
        assert_eq!(val, TealValue::Bytes(app_address(42).to_vec()));
    }

    #[test]
    fn app_params_get_not_found() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.app_params_get(999, 0).unwrap();
        assert!(!exists);
        assert_eq!(val, TealValue::Uint(0));
    }

    // ---- acct_params_get tests ----

    #[test]
    fn acct_params_get_found() {
        let addr = [10u8; 32];
        let txn = make_pay_txn(addr, [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.accounts.insert(
            Address(addr),
            AccountData {
                micro_algos: 5_000_000,
                total_created_apps: 2,
                total_apps_opted_in: 3,
                total_assets_opted_in: 4,
                total_created_assets: 1,
                total_extra_app_pages: 1,
                total_boxes: 10,
                total_box_bytes: 500,
                ..Default::default()
            },
        );

        let ctx = make_context(&mut store, vec![txn]);

        // AcctBalance
        let (val, exists) = ctx.acct_params_get(&addr, 0).unwrap();
        assert!(exists);
        assert_eq!(val, TealValue::Uint(5_000_000));

        // AcctTotalAppsCreated
        let (val, _) = ctx.acct_params_get(&addr, 6).unwrap();
        assert_eq!(val, TealValue::Uint(2));

        // AcctTotalAssets
        let (val, _) = ctx.acct_params_get(&addr, 9).unwrap();
        assert_eq!(val, TealValue::Uint(4));

        // AcctTotalBoxes
        let (val, _) = ctx.acct_params_get(&addr, 10).unwrap();
        assert_eq!(val, TealValue::Uint(10));
    }

    #[test]
    fn acct_params_get_not_found() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.acct_params_get(&[99u8; 32], 0).unwrap();
        assert!(!exists);
        assert_eq!(val, TealValue::Uint(0));
    }

    // ---- LogicSig args tests ----

    #[test]
    fn lsig_args() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_lsig_args(vec![b"a".to_vec(), b"b".to_vec()]);

        assert_eq!(ctx.num_args(), 2);
        assert_eq!(ctx.arg(0).unwrap(), b"a");
        assert_eq!(ctx.arg(1).unwrap(), b"b");
        assert!(ctx.arg(2).is_err());
    }

    // ---- Logging tests ----

    #[test]
    fn log_messages() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);

        ctx.log(b"hello".to_vec()).unwrap();
        ctx.log(b"world".to_vec()).unwrap();

        assert_eq!(ctx.logs().len(), 2);
        assert_eq!(ctx.logs()[0], b"hello");
        assert_eq!(ctx.logs()[1], b"world");
    }

    // ---- gload tests ----

    #[test]
    fn gload_default_zero() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let val = ctx.gload(0, 0).unwrap();
        assert_eq!(val, TealValue::Uint(0));
    }

    #[test]
    fn gload_out_of_range() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.gload(5, 0).is_err());
    }

    // ---- Inner transaction tests ----

    #[test]
    fn inner_txn_build_and_submit() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.num_inner_txns(), 0);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(15, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(6, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(7, TealValue::Uint(999)).unwrap(); // Amount
        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 1);

        // Read back fields from last inner txn
        let type_val = ctx.last_itxn_field(14, None).unwrap(); // Type
        assert_eq!(type_val, TealValue::Bytes(b"pay".to_vec()));

        let amount_val = ctx.last_itxn_field(7, None).unwrap(); // Amount
        assert_eq!(amount_val, TealValue::Uint(999));

        let rcv_val = ctx.last_itxn_field(6, None).unwrap(); // Receiver
        assert_eq!(rcv_val, TealValue::Bytes([30u8; 32].to_vec()));
    }

    #[test]
    fn inner_txn_group() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(15, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(7, TealValue::Uint(100)).unwrap();

        ctx.itxn_next().unwrap();
        ctx.itxn_field(15, TealValue::Uint(4)).unwrap(); // axfer
        ctx.itxn_field(17, TealValue::Uint(200)).unwrap(); // AssetAmount

        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 2);

        // Read from the group
        let val = ctx.last_itxn_group_field(0, 7, None).unwrap(); // Amount of first
        assert_eq!(val, TealValue::Uint(100));

        let val = ctx.last_itxn_group_field(1, 17, None).unwrap(); // AssetAmount of second
        assert_eq!(val, TealValue::Uint(200));
    }

    #[test]
    fn inner_txn_errors() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);

        // field before begin
        assert!(ctx.itxn_field(0, TealValue::Uint(0)).is_err());
        // submit before begin
        assert!(ctx.itxn_submit().is_err());
        // next before begin
        assert!(ctx.itxn_next().is_err());
        // last_itxn_field with no submitted txns
        assert!(ctx.last_itxn_field(0, None).is_err());
    }

    // ---- Execution mode ----

    #[test]
    fn execution_mode_and_identity() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.is_app_mode());
        assert_eq!(ctx.current_app_id(), 42);
        assert_eq!(ctx.program_hash(), [2u8; 32]);
    }

    // ---- Accounts[0] = sender edge cases ----

    #[test]
    fn txn_field_accounts_zero_is_sender_empty_accounts() {
        // Even when there are no foreign accounts, Accounts[0] should return the sender.
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let a0 = ctx.txn_field(0, 27, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Bytes(sender.to_vec()));

        // NumAccounts = 0 (no foreign accounts)
        assert_eq!(ctx.txn_field(0, 28, None).unwrap(), TealValue::Uint(0));

        // Accounts[1] should fail (no foreign accounts)
        assert!(ctx.txn_field(0, 27, Some(1)).is_err());
    }

    // ---- Applications[0] = current app edge cases ----

    #[test]
    fn txn_field_applications_zero_is_current_app_empty_foreign() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // Applications[0] = current ApplicationID even with no foreign apps
        let a0 = ctx.txn_field(0, 49, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Uint(42));

        // NumApplications = 0
        assert_eq!(ctx.txn_field(0, 50, None).unwrap(), TealValue::Uint(0));

        // Applications[1] should fail
        assert!(ctx.txn_field(0, 49, Some(1)).is_err());
    }

    // ---- Program page tests ----

    #[test]
    fn program_pages_single_page() {
        let sender = [10u8; 32];
        let program = vec![0x06, 0x81, 0x01]; // short program (3 bytes < 4096)
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".to_string();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 1
        assert_eq!(ctx.txn_field(0, 64, None).unwrap(), TealValue::Uint(1));

        // ApprovalProgramPages[0] = entire program
        assert_eq!(
            ctx.txn_field(0, 63, Some(0)).unwrap(),
            TealValue::Bytes(program)
        );

        // ApprovalProgramPages[1] = out of range → error
        assert!(ctx.txn_field(0, 63, Some(1)).is_err());
    }

    #[test]
    fn program_pages_multi_page() {
        let sender = [10u8; 32];
        // Create a program that spans 2 pages (4097 bytes)
        let program: Vec<u8> = (0..4097u16).map(|i| (i % 256) as u8).collect();
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".to_string();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 2 (4097 / 4096 = 2)
        assert_eq!(ctx.txn_field(0, 64, None).unwrap(), TealValue::Uint(2));

        // Page 0 = first 4096 bytes
        assert_eq!(
            ctx.txn_field(0, 63, Some(0)).unwrap(),
            TealValue::Bytes(program[..4096].to_vec())
        );

        // Page 1 = remaining 1 byte
        assert_eq!(
            ctx.txn_field(0, 63, Some(1)).unwrap(),
            TealValue::Bytes(program[4096..].to_vec())
        );

        // Page 2 = out of range
        assert!(ctx.txn_field(0, 63, Some(2)).is_err());
    }

    #[test]
    fn program_pages_empty_program() {
        let sender = [10u8; 32];
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".to_string();
        txn.txn.approval_program = None;
        txn.txn.clear_state_program = None;
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 0 for empty/None program
        assert_eq!(ctx.txn_field(0, 64, None).unwrap(), TealValue::Uint(0));
        // NumClearStateProgramPages = 0
        assert_eq!(ctx.txn_field(0, 66, None).unwrap(), TealValue::Uint(0));

        // Page 0 on empty program = error (0 pages, index 0 is OOB)
        assert!(ctx.txn_field(0, 63, Some(0)).is_err());
        assert!(ctx.txn_field(0, 65, Some(0)).is_err());
    }

    #[test]
    fn program_pages_exact_page_boundary() {
        let sender = [10u8; 32];
        // Exactly 4096 bytes = 1 page, not 2
        let program = vec![0xAA; 4096];
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".to_string();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.txn_field(0, 64, None).unwrap(), TealValue::Uint(1));
        assert_eq!(
            ctx.txn_field(0, 63, Some(0)).unwrap(),
            TealValue::Bytes(program)
        );
        assert!(ctx.txn_field(0, 63, Some(1)).is_err());
    }

    // ---- div_ceil helper test ----

    #[test]
    fn test_div_ceil() {
        assert_eq!(super::div_ceil(0, 4096), 0);
        assert_eq!(super::div_ceil(1, 4096), 1);
        assert_eq!(super::div_ceil(4096, 4096), 1);
        assert_eq!(super::div_ceil(4097, 4096), 2);
        assert_eq!(super::div_ceil(8192, 4096), 2);
        assert_eq!(super::div_ceil(8193, 4096), 3);
    }
}
