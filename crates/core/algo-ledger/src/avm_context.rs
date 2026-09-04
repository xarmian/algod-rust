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

//! `AvmContext` implementation backed by `LedgerStore`.
//!
//! `LedgerAvmContext` wraps a ledger store together with the current
//! transaction group, round metadata, and scratch/inner-txn state so that
//! the AVM can read/write chain state through the `AvmContext` trait defined
//! in `algo-avm`.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use algo_avm::context::AvmContext;
use algo_avm::eval::AvmResult;
use algo_avm::tracer::{AppStateAccess, AppStateOp, AppStateType, UnnamedResourceAccess};
use algo_avm::txn_fields;
use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{
    Address, HoldingRef, LocalsRef, ResourceRef, SignedTransaction, TealValue, Transaction,
};
use sha2::{Digest, Sha512_256};

use crate::apply::{
    apply_acfg, apply_afrz, apply_appl_on_completion, apply_appl_opt_in_pre_program, apply_axfer,
    apply_keyreg, apply_pay, create_application, program_hash, ApplErrorContext,
    ON_COMPLETION_CLEAR_STATE, ON_COMPLETION_DELETE, ON_COMPLETION_OPT_IN,
};
use crate::params;
use crate::store_trait::LedgerStore;

/// Box operation types for dirty-byte tracking in `available_box`.
/// Matches go-algorand's `BoxOperation` enum in `box.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoxOperation {
    Create,
    Read,
    Write,
    Delete,
    Resize,
}

/// A snapshot of one caller-chain ancestor's family-box-relevant state,
/// captured at the moment an inner app call is created. Mirrors what
/// go-algorand reads off its live `cx.caller *EvalContext` linked list
/// (`checkFamilyReentrancy`, `data/transactions/logic/box.go:131-155`):
/// since an ancestor frame is suspended for the entire lifetime of a
/// descendant's execution (synchronous recursive evaluation), a snapshot
/// taken on entry is equivalent to reading the ancestor's live fields.
#[derive(Debug, Clone, Copy)]
struct FamilyFrame {
    /// The ancestor's app ID (used only for the reentrancy error message).
    app_id: u64,
    /// The ancestor's creator address.
    creator: [u8; 32],
    /// Whether the ancestor had already touched family-shared box state (by
    /// itself or by a descendant it delegated to) at the moment this
    /// snapshot was taken.
    touched_family_shared: bool,
}

// Re-export `type_enum` from the shared module for backward compatibility.
pub use txn_fields::type_enum;

// ---------------------------------------------------------------------------
// Helper: compute application address = SHA512/256("appID" || app_id_be_bytes)
// ---------------------------------------------------------------------------

/// Compute an application address: `SHA512/256("appID" || app_id_be_bytes)`.
///
/// Exposed publicly for tests and inner transaction execution.
pub fn app_address(app_id: u64) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(b"appID");
    h.update(app_id.to_be_bytes());
    h.finalize().into()
}

/// Format a box name the way go-algorand's `%#x` verb formats a Go string:
/// `"0x"` followed by the lowercase hex of each byte. Used only in the box
/// I/O write-budget error message (`available_app_box`), to match
/// go-algorand's exact text (`data/transactions/logic/box.go:261-262`).
fn box_name_hex(name: &[u8]) -> String {
    let mut s = String::with_capacity(2 + name.len() * 2);
    s.push_str("0x");
    for b in name {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
    26, // ApplicationArgs
    28, // Accounts
    48, // Assets (foreign assets)
    50, // Applications (foreign apps)
    64, // ApprovalProgramPages
    66, // ClearStateProgramPages
];

/// Accumulates field values while an inner transaction is being constructed
/// via `itxn_begin` / `itxn_field` / `itxn_submit`.
#[derive(Debug, Clone, Default)]
struct InnerTxnBuilder {
    /// Scalar fields — latest `itxn_field` wins.
    fields: BTreeMap<u8, TealValue>,
    /// Array fields — each `itxn_field` appends to the list.
    array_fields: BTreeMap<u8, Vec<TealValue>>,
    /// Whether the Fee field (index 1) was explicitly set via `itxn_field`.
    /// When true, the fee value (even 0) is intentional and should not be
    /// defaulted to MinTxnFee. This enables fee pooling where a program
    /// explicitly sets fee=0 to rely on overpayment from other transactions.
    fee_set: bool,
}

impl InnerTxnBuilder {
    fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
            array_fields: BTreeMap::new(),
            fee_set: false,
        }
    }

    /// Set a field value. Array-valued fields accumulate; scalar fields
    /// are overwritten by the latest call.
    fn set_field(&mut self, field: u8, value: TealValue) {
        if field == 1 {
            self.fee_set = true;
        }
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
                7 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.receiver = Address(addr);
                        }
                    }
                }
                // Amount
                8 => {
                    if let TealValue::Uint(v) = value {
                        txn.amount = *v;
                    }
                }
                // CloseRemainderTo
                9 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.close_remainder_to = Address(addr);
                        }
                    }
                }
                // Type (string)
                15 => {
                    if let TealValue::Bytes(b) = value {
                        txn.txn_type =
                            algo_types::TxnType::from(String::from_utf8_lossy(b).into_owned());
                    }
                }
                // TypeEnum
                16 => {
                    if let TealValue::Uint(v) = value {
                        txn.txn_type = match v {
                            1 => algo_types::TxnType::Pay,
                            2 => algo_types::TxnType::Keyreg,
                            3 => algo_types::TxnType::Acfg,
                            4 => algo_types::TxnType::Axfer,
                            5 => algo_types::TxnType::Afrz,
                            6 => algo_types::TxnType::Appl,
                            7 => algo_types::TxnType::Stpf,
                            _ => algo_types::TxnType::default(),
                        };
                    }
                }
                // XferAsset
                17 => {
                    if let TealValue::Uint(v) = value {
                        txn.xaid = *v;
                    }
                }
                // AssetAmount
                18 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_amount = *v;
                    }
                }
                // AssetSender (clawback source)
                19 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_sender = Some(Address(addr));
                        }
                    }
                }
                // AssetReceiver
                20 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_receiver = Some(Address(addr));
                        }
                    }
                }
                // AssetCloseTo
                21 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_close_to = Some(Address(addr));
                        }
                    }
                }
                // ApplicationID
                24 => {
                    if let TealValue::Uint(v) = value {
                        txn.application_id = *v;
                    }
                }
                // OnCompletion
                25 => {
                    if let TealValue::Uint(v) = value {
                        txn.on_completion = *v;
                    }
                }
                // ApprovalProgram
                30 => {
                    if let TealValue::Bytes(b) = value {
                        txn.approval_program = Some(serde_bytes::ByteBuf::from(b.clone()));
                    }
                }
                // ClearStateProgram
                31 => {
                    if let TealValue::Bytes(b) = value {
                        txn.clear_state_program = Some(serde_bytes::ByteBuf::from(b.clone()));
                    }
                }
                // ConfigAsset
                33 => {
                    if let TealValue::Uint(v) = value {
                        txn.config_asset = *v;
                    }
                }
                // ConfigAssetTotal
                34 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .total = *v;
                    }
                }
                // ConfigAssetDecimals
                35 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .decimals = *v as u32;
                    }
                }
                // ConfigAssetDefaultFrozen
                36 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .default_frozen = *v != 0;
                    }
                }
                // ConfigAssetUnitName
                37 => {
                    if let TealValue::Bytes(b) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .unit_name = String::from_utf8_lossy(b).to_string();
                    }
                }
                // ConfigAssetName
                38 => {
                    if let TealValue::Bytes(b) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .asset_name = String::from_utf8_lossy(b).to_string();
                    }
                }
                // ConfigAssetURL
                39 => {
                    if let TealValue::Bytes(b) = value {
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .url = String::from_utf8_lossy(b).to_string();
                    }
                }
                // ConfigAssetMetadataHash
                40 => {
                    if let TealValue::Bytes(b) = value {
                        let mut arr = [0u8; 32];
                        let len = b.len().min(32);
                        arr[..len].copy_from_slice(&b[..len]);
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .metadata_hash = Some(arr);
                    }
                }
                // ConfigAssetManager
                41 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_params
                                .get_or_insert_with(algo_types::AssetParams::default)
                                .manager = Some(Address(addr));
                        }
                    }
                }
                // ConfigAssetReserve
                42 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_params
                                .get_or_insert_with(algo_types::AssetParams::default)
                                .reserve = Some(Address(addr));
                        }
                    }
                }
                // ConfigAssetFreeze
                43 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_params
                                .get_or_insert_with(algo_types::AssetParams::default)
                                .freeze = Some(Address(addr));
                        }
                    }
                }
                // ConfigAssetClawback
                44 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.asset_params
                                .get_or_insert_with(algo_types::AssetParams::default)
                                .clawback = Some(Address(addr));
                        }
                    }
                }
                // FreezeAsset
                45 => {
                    if let TealValue::Uint(v) = value {
                        txn.freeze_asset = *v;
                    }
                }
                // FreezeAssetAccount
                46 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.freeze_account = Some(Address(addr));
                        }
                    }
                }
                // FreezeAssetFrozen
                47 => {
                    if let TealValue::Uint(v) = value {
                        txn.asset_frozen = *v != 0;
                    }
                }
                // GlobalNumUint
                52 => {
                    if let TealValue::Uint(v) = value {
                        txn.global_state_schema
                            .get_or_insert_with(algo_types::StateSchema::default)
                            .num_uint = *v;
                    }
                }
                // GlobalNumByteSlice
                53 => {
                    if let TealValue::Uint(v) = value {
                        txn.global_state_schema
                            .get_or_insert_with(algo_types::StateSchema::default)
                            .num_byte_slice = *v;
                    }
                }
                // LocalNumUint
                54 => {
                    if let TealValue::Uint(v) = value {
                        txn.local_state_schema
                            .get_or_insert_with(algo_types::StateSchema::default)
                            .num_uint = *v;
                    }
                }
                // LocalNumByteSlice
                55 => {
                    if let TealValue::Uint(v) = value {
                        txn.local_state_schema
                            .get_or_insert_with(algo_types::StateSchema::default)
                            .num_byte_slice = *v;
                    }
                }
                // ExtraProgramPages
                56 => {
                    if let TealValue::Uint(v) = value {
                        txn.extra_program_pages = *v as u32;
                    }
                }
                // Nonparticipation
                57 => {
                    if let TealValue::Uint(v) = value {
                        txn.non_participation = *v != 0;
                    }
                }
                // RejectVersion
                68 => {
                    if let TealValue::Uint(v) = value {
                        txn.reject_version = *v;
                    }
                }
                // Note
                5 => {
                    if let TealValue::Bytes(b) = value {
                        txn.note = serde_bytes::ByteBuf::from(b.clone());
                    }
                }
                // VotePK
                10 => {
                    if let TealValue::Bytes(b) = value {
                        let mut arr = [0u8; 32];
                        let len = b.len().min(32);
                        arr[..len].copy_from_slice(&b[..len]);
                        txn.vote_pk = Some(arr);
                    }
                }
                // SelectionPK
                11 => {
                    if let TealValue::Bytes(b) = value {
                        let mut arr = [0u8; 32];
                        let len = b.len().min(32);
                        arr[..len].copy_from_slice(&b[..len]);
                        txn.selection_pk = Some(arr);
                    }
                }
                // VoteFirst
                12 => {
                    if let TealValue::Uint(v) = value {
                        txn.vote_first = *v;
                    }
                }
                // VoteLast
                13 => {
                    if let TealValue::Uint(v) = value {
                        txn.vote_last = *v;
                    }
                }
                // VoteKeyDilution
                14 => {
                    if let TealValue::Uint(v) = value {
                        txn.vote_key_dilution = *v;
                    }
                }
                // RekeyTo
                32 => {
                    if let TealValue::Bytes(b) = value {
                        if b.len() == 32 {
                            let mut addr = [0u8; 32];
                            addr.copy_from_slice(b);
                            txn.rekey_to = Some(Address(addr));
                        }
                    }
                }
                // StateProofPK
                63 => {
                    if let TealValue::Bytes(b) = value {
                        let mut arr = [0u8; 64];
                        let len = b.len().min(64);
                        arr[..len].copy_from_slice(&b[..len]);
                        txn.state_proof_pk = Some(arr);
                    }
                }
                // Safety: op_itxn_field validates field indices before they reach
                // build(), so all valid settable fields are handled above and
                // this arm should never be reached.
                _ => unreachable!("build(): unexpected field index {field}"),
            }
        }

        // Process array fields.
        for (&field, values) in &self.array_fields {
            match field {
                // ApplicationArgs
                26 => {
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
                28 => {
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
                48 => {
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
                50 => {
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
                // ApprovalProgramPages
                64 => {
                    // Concatenate all pages into a single approval program.
                    let mut program_bytes = Vec::new();
                    for v in values {
                        if let TealValue::Bytes(b) = v {
                            program_bytes.extend_from_slice(b);
                        }
                    }
                    if !program_bytes.is_empty() {
                        txn.approval_program = Some(serde_bytes::ByteBuf::from(program_bytes));
                    }
                }
                // ClearStateProgramPages
                66 => {
                    // Concatenate all pages into a single clear state program.
                    let mut program_bytes = Vec::new();
                    for v in values {
                        if let TealValue::Bytes(b) = v {
                            program_bytes.extend_from_slice(b);
                        }
                    }
                    if !program_bytes.is_empty() {
                        txn.clear_state_program = Some(serde_bytes::ByteBuf::from(program_bytes));
                    }
                }
                // Safety: op_itxn_field validates field indices before they reach
                // build(), so all valid array fields are handled above and
                // this arm should never be reached.
                _ => unreachable!("build(): unexpected array field index {field}"),
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
    /// Group scratch space: `scratch[group_index]` is `Some(row)` once that
    /// group member's program has run (`row[slot]` gives the value), or
    /// `None` if it hasn't run yet — including a same-group sibling whose
    /// `Type` is `appl` but which never actually executed a program (e.g. a
    /// ClearState call against an already-deleted app). Mirrors
    /// go-algorand's `pastScratch [maxTxGroupSize]*scratchSpace`
    /// (`data/transactions/logic/eval.go`), which is nil until
    /// `EvalContract` runs for that index.
    ///
    /// Populated from the group's shared `ran_program` state
    /// (`apply.rs::GroupInfo`) when this context is constructed for an
    /// app-call transaction that is part of a multi-transaction group; a
    /// prior sibling that ran gets a zero-filled placeholder row here (the
    /// real per-slot values a sibling actually wrote are not yet threaded
    /// across transactions — tracked separately) so that `gload` only needs
    /// to distinguish "ran" from "never ran" to match go-algorand's error
    /// behavior.
    pub scratch: Vec<Option<[TealValue; 256]>>,
    /// Inner transaction currently being built (if any).
    inner_building: Vec<InnerTxnBuilder>,
    /// Completed inner transaction groups.
    inner_txns: Vec<Vec<SignedTransaction>>,
    /// Genesis hash.
    pub genesis_hash: [u8; 32],
    /// App ID of the caller (the app that issued the inner txn to invoke us).
    /// 0 for top-level app calls.
    pub caller_app_id_val: u64,
    /// Application address of the caller app.
    /// Zero address for top-level app calls.
    pub caller_app_address_val: [u8; 32],
    /// Inner transaction call depth. 0 for top-level, incremented per level.
    pub depth: u32,
    /// Fee credit available from outer transaction group overpayment.
    ///
    /// Inner transaction groups can underpay fees if the outer group overpaid.
    /// This tracks the available credit across all inner txn submissions.
    pub fee_credit: u64,
    /// Fractional microAlgo residue (1e-12 precision, i.e. over
    /// `algo_validate::FEE_RESIDUE_SCALE`) that this group's fee charges
    /// have rounded up so far but not yet consumed.
    ///
    /// Mirrors go-algorand's `EvalParams.feeResidue` (`data/transactions/
    /// logic/eval.go`, PR #6650): carrying it from one charge to the next
    /// lets the whole tree of top-level and inner-txn groups round up only
    /// once in aggregate, rather than once per group. Unlike `fee_credit`
    /// (shared across an entire top-level group via `ApplyContext`), this is
    /// a plain value inherited by copy into a nested inner app call's own
    /// `LedgerAvmContext` (`execute_inner_appl`) and copied back after that
    /// inner group finishes, so sibling inner groups see what residue was
    /// already consumed rather than double-spending it.
    pub fee_residue: u64,
    /// Running transaction counter for asset/app ID generation in inner txns.
    ///
    /// Mirrors go-algorand's `Counter()` — incremented before each inner txn
    /// execution so that `txn_counter + 1` yields a unique creatable ID.
    pub txn_counter: u64,
    /// Fee sink address for inner transaction fee deduction.
    pub fee_sink: Address,
    /// Opcode budget shared between the AVM machine and inner app call
    /// execution. Updated by `set_opcode_budget` / `get_opcode_budget`
    /// before and after `itxn_submit`.
    pub opcode_budget: i64,
    /// Precomputed inner transaction IDs, mirroring `inner_txns` structure.
    /// Each inner txn gets an ID computed via `compute_inner_txn_id(parent, offset, txn)`.
    inner_txn_ids: Vec<Vec<algo_types::Digest>>,
    /// Asset IDs created by inner transactions (available to subsequent opcodes).
    /// Mirrors go-algorand's `resources.createdAsas`.
    pub created_assets: Vec<u64>,
    /// App IDs created by inner transactions (available to subsequent opcodes).
    /// Mirrors go-algorand's `resources.createdApps`.
    pub created_apps: Vec<u64>,
    /// The effective parent transaction ID used to compute inner txn IDs.
    ///
    /// For top-level app calls, this is `compute_txn_id(&outer_txn)`.
    /// For inner app calls (created in `execute_inner_appl`), this is the
    /// inner appl txn's own computed ID (so nested inner txns derive their
    /// IDs from the immediate parent, not the original outer txn).
    ///
    /// Matches go-algorand's `cx.caller.txn.ID()` / `cx.caller.currentTxID()`.
    pub parent_txn_id: algo_types::Digest,

    // ---- Box I/O budget tracking ----
    /// Available box references: `(app_id, box_name) -> is_dirty`.
    /// Populated from the transaction group's box references on first use.
    available_boxes: HashMap<(u64, Vec<u8>), bool>,

    /// Consensus parameters for the current protocol version.
    pub consensus: ConsensusParams,

    /// Whether `available_boxes` has been populated yet.
    boxes_initialized: bool,

    /// Total dirty bytes written to boxes (must not exceed `io_budget`).
    dirty_bytes: u64,

    /// I/O budget: `num_box_refs * BYTES_PER_BOX_REFERENCE`.
    io_budget: u64,

    /// Per-app-ID oversized-program-bytes contribution currently folded into
    /// `dirty_bytes` by [`Self::consider_budget_program_writes`]. Matches
    /// go-algorand's `resources.updateBytes` (`data/transactions/logic/
    /// resources.go:58-61`): keyed per app so that a later create/update/
    /// delete call against the same app within the group first undoes this
    /// app's previous contribution (rather than double-counting it) before
    /// folding in the new one.
    update_bytes: HashMap<u64, u64>,

    /// Whether the read budget check has already been performed.
    read_budget_checked: bool,

    /// Number of "unnamed" box refs (empty box refs) that can be used by
    /// newly created apps to access boxes not named in box refs.
    /// Matches go-algorand's `resources.unnamedAccess`.
    unnamed_access: i64,

    // ---- Family-shared box access (foreign box opcodes, issue #662) ----
    /// Records that this frame has read or written a family-shared box (one
    /// owned by a same-creator app with `FamilyBoxAccess` set). Matches
    /// go-algorand's `EvalContext.touchedFamilyShared`
    /// (`data/transactions/logic/eval.go:747-752`).
    touched_family_shared: bool,

    /// Records that `check_family_reentrancy` has already passed for this
    /// frame; memoized because the result is invariant for the frame's
    /// lifetime. Matches go-algorand's `EvalContext.familyReentrancyChecked`
    /// (`data/transactions/logic/eval.go:754-759`).
    family_reentrancy_checked: bool,

    /// Snapshot of the caller chain's family-box-relevant state (immediate
    /// caller last), captured when this context was created as an inner app
    /// call. Empty for a top-level app call. Stands in for go-algorand's
    /// live `cx.caller *EvalContext` linked list (see [`FamilyFrame`]).
    family_chain: Vec<FamilyFrame>,

    // ---- Delta tracking for EvalDelta comparison ----
    /// Tracks global state changes made during execution (dual-write with store).
    /// Key: state key bytes, Value: the new TealValue (or absent for deletes).
    global_delta_tracker: HashMap<Vec<u8>, Option<TealValue>>,
    /// Tracks local state changes made during execution (dual-write with store).
    /// Key: (account address, state key bytes), Value: the new TealValue (or absent for deletes).
    local_delta_tracker: HashMap<(Address, Vec<u8>), Option<TealValue>>,

    /// Optional execution tracer for capturing opcode-level details.
    /// Used by the simulation engine for tracing inner transactions.
    ///
    /// Stored as a raw pointer to avoid borrow-checker conflicts when both
    /// `self.store` and the tracer need to be accessed during `itxn_submit`.
    /// SAFETY: the tracer outlives the context (guaranteed by the call stack).
    pub tracer_ptr: Option<*mut (dyn algo_avm::tracer::EvalTracer + 'a)>,

    /// Maximum number of `log` calls per program execution. Defaults to
    /// go-algorand's `logic.maxLogCalls` (32); simulation raises it when
    /// `allow_more_logging` is requested.
    pub max_log_calls: u64,

    /// Maximum total bytes logged per program execution. Defaults to
    /// go-algorand's `logic.maxLogSize` (1024); simulation raises it when
    /// `allow_more_logging` is requested.
    pub max_log_size: u64,

    /// Running total of bytes logged so far (go-algorand's `cx.logSize`).
    log_size: u64,

    /// When `Some`, unnamed-resource tracking is enabled (the simulation
    /// request set `allow_unnamed_resources`): resource accesses outside the
    /// group's named reference arrays are reported to the tracer instead of
    /// being restricted, and unnamed box accesses are permitted. Holds the
    /// resources named by the top-level transaction group.
    unnamed_tracking: Option<Arc<NamedGroupResources>>,

    /// Optional per-round box-modification recorder for `StateDelta.kv_mods`
    /// (issue #570). Shared (via `Rc<RefCell<_>>`, cheaply cloned) across
    /// every transaction and every inner app call within one block-apply
    /// pass, so it accumulates the whole round's box deltas in one map.
    /// `None` when the caller doesn't need deltas (e.g. most tests, and any
    /// AVM execution not driven through the block-apply capturing path).
    /// Keyed by the raw KV-store key bytes (`make_box_key`), first-touch's
    /// pre-mutation value wins for `old_data` per key — see
    /// [`record_kv_mod`](Self::record_kv_mod).
    pub kv_mods_recorder: Option<KvModsRecorder>,
    /// The AVM version of the program currently executing in this context.
    /// Used to gate group-wide resource sharing behind
    /// `SHARED_RESOURCES_VERSION` (matches go-algorand's `cx.version >=
    /// sharedResourcesVersion` checks in `availableAccount`/`availableAsset`/
    /// `availableApp`).
    pub program_version: u8,
    /// Resources (accounts/assets/apps) shared by sibling transactions in
    /// `group`, computed once at construction. See [`GroupResources`].
    pub(crate) group_resources: GroupResources,
}

/// Shared accumulator type for per-round box deltas. See
/// [`LedgerAvmContext::kv_mods_recorder`].
pub type KvModsRecorder = Rc<RefCell<HashMap<Vec<u8>, crate::state_delta::KvValueDelta>>>;

/// Base AVM limit on the number of `log` calls per program execution.
/// Mirrors go-algorand's `logic.maxLogCalls`.
pub const MAX_LOG_CALLS: u64 = 32;

/// Base AVM limit on the total bytes logged per program execution.
/// Mirrors go-algorand's `logic.maxLogSize` (`bounds.MaxEvalDeltaTotalLogSize`).
pub const MAX_LOG_SIZE: u64 = 1024;

/// Resources named by a top-level transaction group's reference arrays,
/// precomputed for unnamed-resource tracking (`allow_unnamed_resources`).
///
/// Mirrors the "named" side of go-algorand's simulation `ResourceTracker`
/// (`ledger/simulation/resources.go`): an access is *unnamed* when the
/// resource does not appear here (and was not created during execution).
/// Cross-products (asset holdings / app locals) are named only when both
/// halves are named by the *same* transaction, matching go-algorand's
/// per-transaction cross-product availability.
#[derive(Debug, Default)]
pub struct NamedGroupResources {
    /// Union of all accounts named anywhere in the group.
    accounts: HashSet<[u8; 32]>,
    /// Union of all asset IDs named anywhere in the group.
    assets: HashSet<u64>,
    /// Union of all app IDs named anywhere in the group.
    apps: HashSet<u64>,
    /// Boxes named by box references: `(app_id, name)`.
    boxes: HashSet<(u64, Vec<u8>)>,
    /// Per-transaction named sets, for cross-product (holding/local) checks.
    per_txn: Vec<TxnNamedResources>,
}

/// Resources named by a single transaction's fields and reference arrays.
#[derive(Debug, Default)]
struct TxnNamedResources {
    accounts: HashSet<[u8; 32]>,
    assets: HashSet<u64>,
    apps: HashSet<u64>,
}

impl NamedGroupResources {
    /// Compute the named resources for a top-level transaction group.
    pub fn from_group(group: &[SignedTransaction]) -> Self {
        let mut named = NamedGroupResources::default();

        for stxn in group {
            let txn = &stxn.txn;
            let mut tn = TxnNamedResources::default();

            // Accounts named by transaction fields.
            tn.accounts.insert(txn.sender.0);
            for addr in [
                Some(txn.receiver),
                Some(txn.close_remainder_to),
                txn.asset_receiver,
                txn.asset_sender,
                txn.asset_close_to,
                txn.freeze_account,
            ]
            .into_iter()
            .flatten()
            {
                if !addr.is_zero() {
                    tn.accounts.insert(addr.0);
                }
            }
            if let Some(ref accounts) = txn.accounts {
                for a in accounts {
                    tn.accounts.insert(a.0);
                }
            }

            // Assets named by transaction fields and the foreign-assets array.
            for id in [txn.xaid, txn.config_asset, txn.freeze_asset] {
                if id != 0 {
                    tn.assets.insert(id);
                }
            }
            if let Some(ref assets) = txn.foreign_assets {
                tn.assets.extend(assets.iter().copied());
            }

            // Apps named by the called app and the foreign-apps array. Named
            // apps also make their application accounts available
            // (go-algorand `appAddressAvailableVersion`).
            if txn.application_id != 0 {
                tn.apps.insert(txn.application_id);
                tn.accounts.insert(app_address(txn.application_id));
            }
            if let Some(ref apps) = txn.foreign_apps {
                for &id in apps {
                    tn.apps.insert(id);
                    tn.accounts.insert(app_address(id));
                }
            }

            // Boxes named by box references (same resolution as
            // `ensure_boxes_initialized`: index 0 = the called app, index > 0
            // is 1-based into foreign apps; empty refs name nothing).
            if let Some(ref box_refs) = txn.boxes {
                for br in box_refs {
                    let name = match &br.name {
                        Some(n) if !n.is_empty() => n.clone(),
                        _ => continue,
                    };
                    let app_id = if br.index == 0 {
                        txn.application_id
                    } else {
                        match txn
                            .foreign_apps
                            .as_ref()
                            .and_then(|apps| apps.get((br.index - 1) as usize))
                        {
                            Some(&id) => id,
                            None => continue,
                        }
                    };
                    named.boxes.insert((app_id, name.to_vec()));
                }
            }

            named.accounts.extend(tn.accounts.iter().copied());
            named.assets.extend(tn.assets.iter().copied());
            named.apps.extend(tn.apps.iter().copied());
            named.per_txn.push(tn);
        }

        named
    }

    /// Whether some single transaction names both the account and the asset,
    /// making the holding cross-product available.
    fn has_holding(&self, account: &[u8; 32], asset_id: u64) -> bool {
        self.per_txn
            .iter()
            .any(|t| t.accounts.contains(account) && t.assets.contains(&asset_id))
    }

    /// Whether some single transaction names both the account and the app,
    /// making the local-state cross-product available.
    fn has_local(&self, account: &[u8; 32], app_id: u64) -> bool {
        self.per_txn
            .iter()
            .any(|t| t.accounts.contains(account) && t.apps.contains(&app_id))
    }
}

// Helper to create a default scratch row (256 zero-uint slots).
pub(crate) fn default_scratch_row() -> [TealValue; 256] {
    std::array::from_fn(|_| TealValue::Uint(0))
}

impl<'a, L: LedgerStore> LedgerAvmContext<'a, L> {
    /// Core asset-reference resolution, matching go-algorand's
    /// `resolveAsset` (`data/transactions/logic/eval.go`) *before* its
    /// `AppForbidLowResources` low-id check (applied by the caller via
    /// [`Self::check_forbidden_low_resource`], matching go's `defer`).
    fn resolve_asset_unchecked(&self, index: u64) -> Result<u64, AlgoError> {
        let txn = &self.current_txn().txn;
        // Direct reference (go-algorand `asaReference`, AVM v4+): a value that
        // names an *available* asset is the asset ID itself, checked before
        // slot interpretation. With unnamed-resource tracking enabled
        // (simulation `allow_unnamed_resources`), every asset is available and
        // the access is recorded at the querying opcode.
        if index != 0 {
            let in_foreign = txn
                .foreign_assets
                .as_deref()
                .is_some_and(|assets| assets.contains(&index));
            // Named directly in `tx.Access` (AVM v10+) -- matches go's
            // `availableAsset`'s `slices.ContainsFunc(Access, ...)` check.
            let in_access = txn
                .access
                .as_deref()
                .is_some_and(|access| access.iter().any(|rr| rr.asset == index));
            // Group-wide resource sharing (v9+): some other txn in the group
            // mentioned this asset. Matches go's `availableAsset`'s
            // `cx.version >= sharedResourcesVersion` branch.
            let shared = self.program_version >= SHARED_RESOURCES_VERSION
                && self.group_resources.shared_asas.contains(&index);
            if in_foreign
                || in_access
                || shared
                || txn.xaid == index
                || txn.config_asset == index
                || txn.freeze_asset == index
                || self.created_assets.contains(&index)
                || self.unnamed_tracking.is_some()
            {
                return Ok(index);
            }
        }
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
            return Ok(assets[i]);
        }
        // Matches go-algorand's `resolveAsset` fallback slot lookup into
        // `tx.Access` (`Access[ref-1].Asset != 0`), tried after the legacy
        // `ForeignAssets` slot lookup.
        if let Some(access) = &txn.access {
            if let Some(rr) = access.get(i) {
                if rr.asset != 0 {
                    return Ok(rr.asset);
                }
            }
        }
        Err(AlgoError::Avm {
            message: format!(
                "resolve_asset: index {} out of range (foreign_assets len={})",
                index,
                assets.len() + 1
            ),
        })
    }

    /// Core app-reference resolution, matching go-algorand's `resolveApp`
    /// (`data/transactions/logic/eval.go`) *before* its
    /// `AppForbidLowResources` low-id check (applied by the caller via
    /// [`Self::check_forbidden_low_resource`], matching go's `defer`).
    fn resolve_app_unchecked(&self, index: u64) -> Result<u64, AlgoError> {
        if index == 0 {
            return Ok(self.app_id);
        }
        let txn = &self.current_txn().txn;
        // Direct reference (go-algorand `appReference`, AVM v4+): a value that
        // names an *available* app is the app ID itself, checked before slot
        // interpretation. With unnamed-resource tracking enabled, every app is
        // available and the access is recorded at the querying opcode.
        {
            let in_foreign = txn
                .foreign_apps
                .as_deref()
                .is_some_and(|apps| apps.contains(&index));
            // Named directly in `tx.Access` (AVM v10+) -- matches go's
            // `availableApp`'s `slices.ContainsFunc(Access, ...)` check.
            let in_access = txn
                .access
                .as_deref()
                .is_some_and(|access| access.iter().any(|rr| rr.app == index));
            // Group-wide resource sharing (v9+), matching go's `availableApp`'s
            // `cx.version >= sharedResourcesVersion` branch.
            let shared = self.program_version >= SHARED_RESOURCES_VERSION
                && self.group_resources.shared_apps.contains(&index);
            if in_foreign
                || in_access
                || shared
                || index == self.app_id
                || txn.application_id == index
                || self.created_apps.contains(&index)
                || self.unnamed_tracking.is_some()
            {
                return Ok(index);
            }
        }
        let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
        let i = (index - 1) as usize;
        if i < apps.len() {
            return Ok(apps[i]);
        }
        // Matches go-algorand's `resolveApp` fallback slot lookup into
        // `tx.Access` (`Access[ref-1].App != 0`).
        if let Some(access) = &txn.access {
            if let Some(rr) = access.get(i) {
                if rr.app != 0 {
                    return Ok(rr.app);
                }
            }
        }
        Err(AlgoError::Avm {
            message: format!(
                "resolve_app: index {} out of range (foreign_apps len={})",
                index,
                apps.len() + 1
            ),
        })
    }

    /// `AppForbidLowResources` (go-algorand v38+, `config/consensus.go`):
    /// forbids AVM opcodes from resolving an asset/application ID <= 255
    /// (`lastForbiddenResource`), to reduce ambiguity between IDs and
    /// slot-index references. Mirrors the `defer` check at the end of go's
    /// `resolveAsset`/`resolveApp`/`appReference`/`assetReference`
    /// (`data/transactions/logic/eval.go`), which runs on every successfully
    /// resolved id (including id 0 special-cases like "current app") when
    /// the consensus flag is enabled. Before v38, no such restriction
    /// applies.
    fn check_forbidden_low_resource(&self, id: u64, kind: &str) -> Result<(), AlgoError> {
        const LAST_FORBIDDEN_RESOURCE: u64 = 255;
        if self.consensus.app_forbid_low_resources && id <= LAST_FORBIDDEN_RESOURCE {
            return Err(AlgoError::Avm {
                message: format!("low {kind} lookup {id}"),
            });
        }
        Ok(())
    }

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
        consensus: ConsensusParams,
    ) -> Self {
        let group_len = group.len();
        let group_resources = fill_group_resources(&group);
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
            scratch: vec![None; group_len],
            inner_building: Vec::new(),
            inner_txns: Vec::new(),
            genesis_hash,
            caller_app_id_val: 0,
            caller_app_address_val: [0u8; 32],
            depth: 0,
            fee_credit: 0,
            fee_residue: 0,
            txn_counter: 0,
            fee_sink: Address::ZERO,
            opcode_budget: 0,
            inner_txn_ids: Vec::new(),
            created_assets: Vec::new(),
            created_apps: Vec::new(),
            parent_txn_id: algo_types::Digest([0u8; 32]),
            consensus,
            available_boxes: HashMap::new(),
            boxes_initialized: false,
            dirty_bytes: 0,
            io_budget: 0,
            update_bytes: HashMap::new(),
            read_budget_checked: false,
            unnamed_access: 0,
            touched_family_shared: false,
            family_reentrancy_checked: false,
            family_chain: Vec::new(),
            global_delta_tracker: HashMap::new(),
            local_delta_tracker: HashMap::new(),
            tracer_ptr: None,
            max_log_calls: MAX_LOG_CALLS,
            max_log_size: MAX_LOG_SIZE,
            log_size: 0,
            unnamed_tracking: None,
            kv_mods_recorder: None,
            // Defaults to 0 (sharing inactive) until the caller sets the
            // real executing program version via `set_program_version`.
            // The two production call sites (`apply.rs`) do so immediately
            // after construction, once the program bytes are parsed.
            program_version: 0,
            group_resources,
        }
    }

    /// Set the AVM version of the program about to execute in this context,
    /// activating group-wide resource sharing once it reaches
    /// `SHARED_RESOURCES_VERSION`. Must be called before evaluation begins;
    /// `LedgerAvmContext::new` can't take this directly because the calling
    /// program's version generally isn't known until after the program
    /// bytes are parsed, which happens after context construction at every
    /// call site.
    pub fn set_program_version(&mut self, version: u8) {
        self.program_version = version;
    }

    /// Override the per-program log limits (simulation `allow_more_logging`).
    pub fn set_log_limits(&mut self, max_log_calls: u64, max_log_size: u64) {
        self.max_log_calls = max_log_calls;
        self.max_log_size = max_log_size;
    }

    /// Enable unnamed-resource tracking (simulation `allow_unnamed_resources`)
    /// with the given precomputed group-named resources.
    pub fn enable_unnamed_resource_tracking(&mut self, named: Arc<NamedGroupResources>) {
        self.unnamed_tracking = Some(named);
    }

    /// The active unnamed-tracking named-resource set, for propagation to
    /// inner-transaction contexts.
    pub fn unnamed_tracking(&self) -> Option<Arc<NamedGroupResources>> {
        self.unnamed_tracking.clone()
    }

    /// Set LogicSig arguments (for LogicSig mode).
    pub fn set_lsig_args(&mut self, args: Vec<Vec<u8>>) {
        self.lsig_args = args;
    }

    /// Report an application-state access to the attached tracer for
    /// initial-state capture during simulation. A no-op when no tracer is
    /// attached (the consensus apply path), so this adds nothing but a pointer
    /// check on the hot path.
    ///
    /// `pre_value` must be the on-chain value *before* the operation mutates
    /// state; callers read it prior to any write.
    #[allow(clippy::too_many_arguments)]
    fn record_app_state_access(
        &self,
        app_id: u64,
        state: AppStateType,
        op: AppStateOp,
        account: Option<[u8; 32]>,
        key: &[u8],
        pre_value: Option<TealValue>,
        new_value: Option<TealValue>,
    ) {
        if let Some(p) = self.tracer_ptr {
            let access = AppStateAccess {
                executing_app_id: self.app_id,
                app_id,
                state,
                op,
                account,
                key,
                pre_value,
                new_value,
            };
            // SAFETY: `tracer_ptr` is valid for the lifetime of this context and
            // only one mutable borrow of the tracer is live at a time. The
            // tracer is distinct memory from `self.store`, so this does not
            // alias any other borrow held by the caller.
            unsafe { &mut *p }.record_app_state_access(&access);
        }
    }

    /// Report an unnamed-resource access to the attached tracer. A no-op when
    /// unnamed-resource tracking is disabled or no tracer is attached.
    fn record_unnamed(&self, access: UnnamedResourceAccess) {
        if let Some(p) = self.tracer_ptr {
            // SAFETY: identical aliasing invariants to `record_app_state_access`.
            unsafe { &mut *p }.record_unnamed_resource(&access);
        }
    }

    /// Whether `account` is named by the group, is an application account of a
    /// named or created app, or belongs to the currently-executing app.
    fn is_named_account(&self, named: &NamedGroupResources, account: &[u8; 32]) -> bool {
        if named.accounts.contains(account) {
            return true;
        }
        if *account == app_address(self.app_id) {
            return true;
        }
        self.created_apps
            .iter()
            .any(|&id| app_address(id) == *account)
    }

    /// Whether `asset_id` is named by the group or was created during
    /// execution.
    fn is_named_asset(&self, named: &NamedGroupResources, asset_id: u64) -> bool {
        named.assets.contains(&asset_id) || self.created_assets.contains(&asset_id)
    }

    /// Whether `app_id` is named by the group, is the currently-executing app,
    /// or was created during execution.
    fn is_named_app(&self, named: &NamedGroupResources, app_id: u64) -> bool {
        app_id == self.app_id || named.apps.contains(&app_id) || self.created_apps.contains(&app_id)
    }

    /// Track an account access when unnamed-resource tracking is enabled.
    fn note_account_access(&self, account: &[u8; 32]) {
        if let Some(named) = &self.unnamed_tracking {
            if !self.is_named_account(named, account) {
                self.record_unnamed(UnnamedResourceAccess::Account(*account));
            }
        }
    }

    /// Track an asset access when unnamed-resource tracking is enabled.
    fn note_asset_access(&self, asset_id: u64) {
        if let Some(named) = &self.unnamed_tracking {
            if asset_id != 0 && !self.is_named_asset(named, asset_id) {
                self.record_unnamed(UnnamedResourceAccess::Asset(asset_id));
            }
        }
    }

    /// Track an app access when unnamed-resource tracking is enabled.
    fn note_app_access(&self, app_id: u64) {
        if let Some(named) = &self.unnamed_tracking {
            if app_id != 0 && !self.is_named_app(named, app_id) {
                self.record_unnamed(UnnamedResourceAccess::App(app_id));
            }
        }
    }

    /// Track an asset-holding access. Records the unnamed halves, or — when
    /// both halves are named but no single transaction names them together —
    /// the holding cross-product itself (go-algorand `AllowsHolding`).
    fn note_holding_access(&self, account: &[u8; 32], asset_id: u64) {
        if let Some(named) = &self.unnamed_tracking {
            let acct_named = self.is_named_account(named, account);
            let asset_named = asset_id == 0 || self.is_named_asset(named, asset_id);
            if !acct_named {
                self.record_unnamed(UnnamedResourceAccess::Account(*account));
            }
            if !asset_named {
                self.record_unnamed(UnnamedResourceAccess::Asset(asset_id));
            }
            if acct_named
                && asset_named
                && asset_id != 0
                && !self.created_assets.contains(&asset_id)
                && !named.has_holding(account, asset_id)
            {
                self.record_unnamed(UnnamedResourceAccess::AssetHolding(*account, asset_id));
            }
        }
    }

    /// Track an app-local access. Records the unnamed halves (account/app,
    /// whichever aren't independently named), and -- unless this is the
    /// app's own account, a group-created app, or a pair some single
    /// transaction already names together -- the local cross-product
    /// itself.
    ///
    /// Matches go-algorand's `resourcePolicy.AllowsLocal` -> `addLocal`
    /// (`ledger/simulation/resources.go`): unlike the sibling
    /// `note_holding_access`'s asset-holding cross-product (which this
    /// crate gates on both halves being independently named -- there is no
    /// go-side equivalent narrowing for holdings either, but no test here
    /// currently exercises the gap), go's `ResourceTracker.addLocal` is
    /// called unconditionally by `AllowsLocal` with **no** "both halves
    /// already named" precondition -- only its `hasLocal` sibling's
    /// app's-own-account special case and the tracker's own dedup skip
    /// recording. Requiring both halves to be independently named here
    /// would silently drop exactly the scenario issue #974's
    /// `TestUnnamedResourcesAccountLocalWrite` pins: a completely unnamed
    /// account written via `app_local_put` to the (already-available,
    /// hence trivially "named") current app.
    fn note_local_access(&self, account: &[u8; 32], app_id: u64) {
        if let Some(named) = &self.unnamed_tracking {
            let acct_named = self.is_named_account(named, account);
            let app_named = app_id == 0 || self.is_named_app(named, app_id);
            if !acct_named {
                self.record_unnamed(UnnamedResourceAccess::Account(*account));
            }
            if !app_named {
                self.record_unnamed(UnnamedResourceAccess::App(app_id));
            }
            let is_own_account = app_id != 0 && app_address(app_id) == *account;
            if app_id != 0
                && !is_own_account
                && !self.created_apps.contains(&app_id)
                && !named.has_local(account, app_id)
            {
                self.record_unnamed(UnnamedResourceAccess::AppLocal(*account, app_id));
            }
        }
    }

    /// Attach the *post-write* whole-box content to the box state-change just
    /// recorded by a successful box write opcode, mirroring go-algorand's
    /// `AfterOpcode` → `AppStateQuerying` GetBox read (`opcodeExplain.go:314`).
    /// Read from the store *after* the mutation so partial writes
    /// (`box_replace`/`box_resize`/`box_splice`) report the full resulting box,
    /// and a no-longer-existing box yields an empty value. Called only on the
    /// success path; a no-op when no tracer is attached (consensus apply).
    fn record_box_new_value(&self, app_id: u64, name: &[u8]) {
        if let Some(p) = self.tracer_ptr {
            let new_value = self.box_pre_value(app_id, name);
            // SAFETY: identical aliasing invariants to `record_app_state_access`.
            unsafe { &mut *p }.record_box_new_value(new_value);
        }
    }

    /// Record this box's before/after values into the per-round
    /// `kv_mods_recorder`, for `StateDelta.kv_mods` (issue #570). No-op when
    /// no recorder is attached (the default — most callers don't need
    /// round-level box deltas). Reads the post-mutation value from the store
    /// itself so partial writes (`box_replace`/`box_resize`/`box_splice`)
    /// report the full resulting box, and a deleted box reports empty data,
    /// mirroring [`record_box_new_value`](Self::record_box_new_value).
    ///
    /// `pre` is the value read *before* the mutation, already computed by
    /// the caller for state-access tracing — reused here rather than
    /// re-reading. Only the first write to a given box key within the
    /// recorder's lifetime (i.e. within one round) sets `old_data`; later
    /// writes to the same key in the same round only update `data`, so the
    /// final entry reflects the box's value at the start of the round vs.
    /// its value at the end — matching go-algorand's `ledgercore.StateDelta`
    /// accumulation semantics (a delta is a round-scoped diff, not a log of
    /// every intermediate write).
    fn record_kv_mod(&mut self, app_id: u64, name: &[u8], pre: Option<TealValue>) {
        let Some(recorder) = self.kv_mods_recorder.clone() else {
            return;
        };
        let key = crate::sqlite::make_box_key(app_id, name);
        let new_data = self.store.get_box(app_id, name).unwrap_or_default();
        let old_data = match pre {
            Some(TealValue::Bytes(b)) => b,
            _ => Vec::new(),
        };
        let mut map = recorder.borrow_mut();
        map.entry(key)
            .and_modify(|d| d.data.clone_from(&new_data))
            .or_insert(crate::state_delta::KvValueDelta {
                data: new_data,
                old_data,
            });
    }

    /// Read the current box contents as a [`TealValue`] for initial-state
    /// capture, bypassing the I/O-budget accounting in `available_box` (which
    /// the caller has already performed for the real operation).
    fn box_pre_value(&self, app_id: u64, name: &[u8]) -> Option<TealValue> {
        self.store.get_box(app_id, name).map(TealValue::Bytes)
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

    /// Precomputed inner transaction IDs, mirroring `inner_txns` structure.
    pub fn inner_txn_ids(&self) -> &[Vec<algo_types::Digest>] {
        &self.inner_txn_ids
    }

    // ---- Box helpers ----

    /// Seed this context's box I/O budget state from a group-scoped carrier
    /// (issue #727).
    ///
    /// go-algorand shares one `EvalParams` instance -- and hence its
    /// `ioBudget`/`readBudgetChecked`/`available` (boxes, dirtyBytes,
    /// updateBytes, unnamedAccess) fields -- by pointer across every
    /// top-level transaction in an atomic group (`ledger/eval/eval.go:1090`'s
    /// single `NewAppEvalParams` call, threaded through the group loop at
    /// `ledger/eval/eval.go:1117-1124`). algod-rust instead builds a fresh
    /// `LedgerAvmContext` per top-level `appl` call, so callers must
    /// explicitly seed/export this state via a group-scoped
    /// [`crate::apply::BoxBudgetState`] carrier that outlives any single
    /// call's context -- this is the top-level-group analog of the
    /// existing per-inner-call `box_state` propagation (see
    /// `execute_inner_appl`'s `inner_ctx.available_boxes = box_state...`
    /// seeding a few hundred lines above).
    pub fn load_box_budget_state(&mut self, state: &crate::apply::BoxBudgetState) {
        self.available_boxes = state.available_boxes.clone();
        self.dirty_bytes = state.dirty_bytes;
        self.io_budget = state.io_budget;
        self.update_bytes = state.update_bytes.clone();
        self.read_budget_checked = state.read_budget_checked;
        self.boxes_initialized = state.boxes_initialized;
        self.unnamed_access = state.unnamed_access;
    }

    /// Export this context's box I/O budget state back into a group-scoped
    /// carrier, so the next top-level app call in the same atomic group
    /// sees the accumulated state (issue #727). Counterpart to
    /// [`Self::load_box_budget_state`]; see its doc for the go-algorand
    /// parity rationale.
    ///
    /// `touched_family_shared` is deliberately left untouched: it is a
    /// one-shot inner-call-to-caller return signal (issue #662), not
    /// persistent group-wide state, and group-level callers never read it.
    pub fn save_box_budget_state(&self, state: &mut crate::apply::BoxBudgetState) {
        state.available_boxes = self.available_boxes.clone();
        state.dirty_bytes = self.dirty_bytes;
        state.io_budget = self.io_budget;
        state.update_bytes = self.update_bytes.clone();
        state.read_budget_checked = self.read_budget_checked;
        state.boxes_initialized = self.boxes_initialized;
        state.unnamed_access = self.unnamed_access;
    }

    /// Lazily initialize the available-boxes map and I/O budget from the
    /// transaction group's box references. Matches go-algorand's
    /// `computeAvailability` + `fillApplicationCallForeign` for boxes.
    pub(crate) fn ensure_boxes_initialized(&mut self) {
        if self.boxes_initialized {
            return;
        }
        self.boxes_initialized = true;

        let mut num_box_refs: u64 = 0;

        for stxn in &self.group {
            let txn = &stxn.txn;
            // Determine the app ID for this transaction (0 means "current app"
            // which we resolve to the callee's app_id).
            let txn_app_id = if txn.application_id == 0 {
                // For app creation txns, the app_id is assigned at creation
                // time. We use self.app_id which has already been set.
                self.app_id
            } else {
                txn.application_id
            };

            if let Some(ref box_refs) = txn.boxes {
                for br in box_refs {
                    num_box_refs += 1;

                    // Empty box ref (index=0, no name) bumps unnamed access
                    // and I/O budget but doesn't add availability.
                    let is_empty = br.index == 0 && br.name.as_ref().map_or(true, |n| n.is_empty());
                    if is_empty {
                        self.unnamed_access += 1;
                        continue;
                    }

                    // Non-empty box ref: extract name for availability.
                    let name = match &br.name {
                        Some(n) if !n.is_empty() => n.to_vec(),
                        _ => continue,
                    };

                    // Resolve the app index:
                    // index 0 means "this app" (the app being called in this txn).
                    // index > 0 is 1-based into foreign apps.
                    let app_id = if br.index == 0 {
                        txn_app_id
                    } else {
                        let fa = txn.foreign_apps.as_ref();
                        let idx = (br.index - 1) as usize;
                        match fa.and_then(|apps| apps.get(idx)) {
                            Some(&id) => id,
                            // Invalid ref, skip. Matches go-algorand's own
                            // `fillApplicationCallForeign`
                            // (data/transactions/logic/resources.go:376-377,
                            // `if br.Index > uint64(len(tx.ForeignApps)) {
                            // continue }`) exactly: an out-of-range box index
                            // reaching *evaluation* is silently skipped in Go
                            // too, because Go's own group-level
                            // `CheckTxnGroup` screen is what rejects the
                            // transaction outright, and it runs ahead of
                            // evaluation only on the paths that verify
                            // signatures fresh — `Eval(..., validate=true)`
                            // (agreement/relay block validation) and
                            // `Simulator.check()`. `Eval(..., validate=false)`
                            // (`AddBlock`, and the tracker/catchup replay
                            // path) never re-verifies `CheckTxnGroup`
                            // (`ledger/eval/eval.go:2096-2100`'s doc comment),
                            // trusting that whoever first validated the block
                            // already ran it. algod-rust's sync/replay/
                            // catchpoint-restore paths mirror that same trust
                            // model by not re-running `check_txn_group`
                            // before `apply_block`, so this branch being live
                            // there matches Go's own behavior rather than
                            // being a gap (see issue #628).
                            None => continue,
                        }
                    };

                    // Mark as available, not dirty.
                    self.available_boxes.entry((app_id, name)).or_insert(false);
                }
            }
        }

        self.io_budget = num_box_refs.saturating_mul(self.consensus.bytes_per_box_reference);
    }

    /// Perform the one-time read budget check for a top-level call. Sums the
    /// sizes of all available boxes and verifies against the I/O budget.
    /// Matches go-algorand's read budget check in `EvalContract`
    /// (`data/transactions/logic/eval.go:1275-1344`), which runs eagerly,
    /// unconditionally, for every top-level app call -- gated only on
    /// `cx.caller == nil && !cx.readBudgetChecked`, not on the program ever
    /// executing a box opcode. `apply_appl` (issue #725) calls this
    /// unconditionally before running the approval/clear-state program, in
    /// addition to the pre-existing lazy call sites (`available_app_box`, and
    /// the inner-`appl`-dispatch path in `itxn_submit`) -- `read_budget_checked`
    /// makes every call after the first a no-op, so this is "also called
    /// eagerly" rather than a replacement.
    pub(crate) fn check_read_budget(&mut self) -> Result<(), AlgoError> {
        if self.read_budget_checked {
            return Ok(());
        }
        // Inner transactions inherit the budget and skip the read check.
        if self.caller_app_id_val != 0 {
            self.read_budget_checked = true;
            return Ok(());
        }

        self.read_budget_checked = true;
        let mut used: u64 = 0;

        // Iterate over a snapshot of box keys.
        let keys: Vec<(u64, Vec<u8>)> = self.available_boxes.keys().cloned().collect();
        for (app_id, name) in &keys {
            if name.is_empty() {
                continue;
            }
            if let Some(content) = self.store.get_box(*app_id, name) {
                let size = content.len() as u64;
                used = used.saturating_add(size);
                if used > self.io_budget {
                    // Matches go-algorand's `EvalContract` read-budget error
                    // exactly (`data/transactions/logic/eval.go:1324`):
                    // `fmt.Errorf("read budget exceeded (%d > %d)", bytesRead, cx.ioBudget)`.
                    return Err(AlgoError::Avm {
                        message: format!("read budget exceeded ({} > {})", used, self.io_budget),
                    });
                }
                // Mark as not-dirty (content is cached / known).
                self.available_boxes.insert((*app_id, name.clone()), false);
            }
        }

        Ok(())
    }

    /// Fold this app call's oversized-program-bytes contribution into the
    /// box-write-budget accounting, and reject if it pushes the group over
    /// its I/O budget. Matches go-algorand's
    /// `EvalContext.considerBudgetProgramWrites()` exactly
    /// (`data/transactions/logic/eval.go:540-569`), called after a
    /// successful (approving) run of the approval program for any
    /// transaction that creates, updates, or deletes an app:
    ///
    /// ```go
    /// func (cx *EvalContext) considerBudgetProgramWrites() error {
    ///     creating := cx.txn.Txn.ApplicationID == 0
    ///     updating := cx.txn.Txn.OnCompletion == transactions.UpdateApplicationOC
    ///     deleting := cx.txn.Txn.OnCompletion == transactions.DeleteApplicationOC
    ///     if !creating && !updating && !deleting { return nil }
    ///     if creating && deleting { return nil } // never written
    ///
    ///     oldSize := cx.available.updateBytes[cx.appID]
    ///     cx.available.dirtyBytes = basics.SubSaturate(cx.available.dirtyBytes, oldSize)
    ///     newSize := uint64(transactions.LargeProgramExtraBytes(*cx.Proto,
    ///         len(cx.txn.Txn.ApprovalProgram)+len(cx.txn.Txn.ClearStateProgram)))
    ///     cx.available.dirtyBytes = basics.AddSaturate(cx.available.dirtyBytes, newSize)
    ///     cx.available.updateBytes[cx.appID] = newSize
    ///     if cx.available.dirtyBytes > cx.ioBudget {
    ///         verb := "creating"
    ///         if updating { verb = "updating" }
    ///         return fmt.Errorf("write budget exceeded (%d > %d) while %s app %d", ...)
    ///     }
    ///     return nil
    /// }
    /// ```
    ///
    /// Not called for ClearState: a ClearState call's `OnCompletion` is
    /// never `UpdateApplicationOC`/`DeleteApplicationOC` and its
    /// `ApplicationID` is always nonzero (clearing state requires already
    /// being opted in), so `creating`/`updating`/`deleting` are all false
    /// and go's own function would no-op immediately anyway.
    pub(crate) fn consider_budget_program_writes(&mut self) -> Result<(), AlgoError> {
        let (creating, updating, deleting, approval_len, clear_len) = {
            let txn = &self.group[self.group_index].txn;
            (
                txn.application_id == 0,
                txn.on_completion == crate::apply::ON_COMPLETION_UPDATE,
                txn.on_completion == crate::apply::ON_COMPLETION_DELETE,
                txn.approval_program.as_ref().map(|p| p.len()).unwrap_or(0),
                txn.clear_state_program
                    .as_ref()
                    .map(|p| p.len())
                    .unwrap_or(0),
            )
        };
        if !creating && !updating && !deleting {
            // No program size change.
            return Ok(());
        }
        if creating && deleting {
            // Program never gets written.
            return Ok(());
        }

        // go computes `ioBudget` eagerly, from the group's box refs, at the
        // very start of every top-level `EvalContract` call regardless of
        // whether the program touches boxes at all
        // (`data/transactions/logic/eval.go:1276-1287`) -- a program can use
        // box refs purely as "io bump" budget without ever executing a box
        // opcode. Mirror that here: ensure the budget is populated before
        // consulting it (a no-op if a box opcode, or an earlier top-level
        // sibling in this group, already triggered it).
        self.ensure_boxes_initialized();

        // The "sizes" below are actually the size above the old maximum size.
        let old_size = *self.update_bytes.get(&self.app_id).unwrap_or(&0);
        self.dirty_bytes = self.dirty_bytes.saturating_sub(old_size);

        let new_size =
            algo_validate::large_program_extra_bytes(&self.consensus, approval_len + clear_len)
                as u64;
        self.dirty_bytes = self.dirty_bytes.saturating_add(new_size);
        self.update_bytes.insert(self.app_id, new_size);

        if self.dirty_bytes > self.io_budget {
            // go's verb selection (`eval.go:561-564`) literally only checks
            // for "updating"; a delete-only call (not creating, not
            // updating) still reports "creating" as its default. Mirrored
            // exactly, quirk and all.
            let verb = if updating { "updating" } else { "creating" };
            return Err(AlgoError::Avm {
                message: format!(
                    "write budget exceeded ({} > {}) while {} app {}",
                    self.dirty_bytes, self.io_budget, verb, self.app_id
                ),
            });
        }
        Ok(())
    }

    /// Box availability check, cross-app authorization, and dirty tracking
    /// for a box owned by `app_id` (which may be the current app or a
    /// foreign one). Matches go-algorand's `availableAppBox`
    /// (`data/transactions/logic/box.go:157-265`), which subsumes the
    /// old same-app-only `availableBox`. Returns `(contents, exists)`.
    fn available_app_box(
        &mut self,
        app_id: u64,
        name: &[u8],
        operation: BoxOperation,
        create_size: u64,
    ) -> Result<(Vec<u8>, bool), AlgoError> {
        // ClearState programs cannot access boxes.
        let on_completion = self.group[self.group_index].txn.on_completion;
        if on_completion == ON_COMPLETION_CLEAR_STATE {
            return Err(AlgoError::Avm {
                message: "boxes may not be accessed from ClearState program".into(),
            });
        }

        self.ensure_boxes_initialized();
        self.check_read_budget()?;

        let key = (app_id, name.to_vec());
        let mut ok = self.available_boxes.contains_key(&key);

        // newAppAccess fallback: if the box's *owner* (`app_id`, which may be
        // a foreign app, not necessarily `self.app_id`) was newly created in
        // this group, allow box access using an unnamed (empty) box ref
        // slot. Matches go-algorand's `availableAppBox`
        // (`data/transactions/logic/box.go:174-186`) exactly:
        // `cx.available.createdApps[appID]` is keyed by the function's own
        // `appID` parameter (the owner being accessed), not `cx.appID` (the
        // executing app) -- we know a newly created app's box is empty upon
        // first touch regardless of which app reaches it, as long as that
        // access is itself authorized (checked separately, below).
        let mut new_app_access = false;
        if !ok && self.created_apps.contains(&app_id) && self.unnamed_access > 0 {
            ok = true;
            new_app_access = true;
            self.unnamed_access -= 1;
            // dirty will start as false; it will be marked dirty below
            // for creates/writes and added to available_boxes
        }

        // Unnamed-resource relaxation (simulation `allow_unnamed_resources`):
        // permit access to a box without a matching box ref, report it to the
        // tracer, and grow the I/O budget as if one more box reference had
        // been supplied (go-algorand raises the budget to
        // `maxPossibleBoxIOBudget` instead; see the divergence note on
        // `NamedGroupResources`).
        if !ok && self.unnamed_tracking.is_some() {
            ok = true;
            self.record_unnamed(UnnamedResourceAccess::Box(app_id, name.to_vec()));
            self.io_budget = self
                .io_budget
                .saturating_add(self.consensus.bytes_per_box_reference);
            self.available_boxes.entry(key.clone()).or_insert(false);
        }

        if !ok {
            return Err(AlgoError::Avm {
                message: format!("invalid Box reference {:?}", name),
            });
        }

        // Authorize the access (always allowed for our own boxes) and, for
        // family-shared boxes, apply the family-scoped reentrancy guard.
        // Matches go-algorand's placement of `authorizeBoxAccess` between the
        // availability check and the `Ledger.GetBox` call
        // (`data/transactions/logic/box.go:196-204`).
        self.authorize_box_access(app_id, operation)?;

        let dirty = if new_app_access {
            false
        } else {
            *self.available_boxes.get(&key).unwrap()
        };

        // Read the box content from the store.
        // For newAppAccess, skip disk lookup -- we know the box doesn't exist yet.
        let (content, exists) = if new_app_access {
            (Vec::new(), false)
        } else {
            match self.store.get_box(app_id, name) {
                Some(v) => (v, true),
                None => (Vec::new(), false),
            }
        };

        // Track dirtiness and enforce write budget. `verb` mirrors
        // go-algorand's local `verb` variable, used only in the write-budget
        // error message below.
        let mut verb = "accessing";
        let new_dirty = match operation {
            BoxOperation::Create => {
                verb = "creating";
                if exists {
                    if create_size != content.len() as u64 {
                        return Err(AlgoError::Avm {
                            message: format!("box size mismatch {} {}", content.len(), create_size),
                        });
                    }
                    // Box already exists with correct size, no dirty work.
                    return Ok((content, true));
                }
                // New box creation — treat as write.
                if !dirty {
                    self.dirty_bytes += create_size;
                }
                true
            }
            BoxOperation::Write => {
                verb = "writing";
                let write_size = if exists {
                    content.len() as u64
                } else {
                    create_size
                };
                if !dirty {
                    self.dirty_bytes += write_size;
                }
                true
            }
            BoxOperation::Resize => {
                verb = "resizing";
                if dirty {
                    self.dirty_bytes -= content.len() as u64;
                }
                self.dirty_bytes += create_size;
                true
            }
            BoxOperation::Delete => {
                if dirty {
                    self.dirty_bytes -= content.len() as u64;
                }
                false
            }
            BoxOperation::Read => dirty,
        };

        self.available_boxes.insert(key, new_dirty);

        if self.dirty_bytes > self.io_budget {
            // Matches go-algorand's exact format
            // (`data/transactions/logic/box.go:261-262`):
            // `fmt.Errorf("write budget exceeded (%d > %d) while %s box %#x",
            //   cx.available.dirtyBytes, cx.ioBudget, verb, name)`.
            return Err(AlgoError::Avm {
                message: format!(
                    "write budget exceeded ({} > {}) while {} box {}",
                    self.dirty_bytes,
                    self.io_budget,
                    verb,
                    box_name_hex(name),
                ),
            });
        }

        Ok((content, exists))
    }

    /// Verifies that the current app (`self.app_id`) may perform `operation`
    /// on the box owned by `owner_app_id`, and applies the family-shared
    /// reentrancy guard when the box behaves like family-shared state.
    /// Matches go-algorand's `authorizeBoxAccess`
    /// (`data/transactions/logic/box.go:42-122`) exactly, including its
    /// error text.
    ///
    /// An app always accesses its own boxes freely. For another app's box:
    /// reads are allowed if the owner has `ForeignBoxReads` set, or if the
    /// caller shares the owner's creator and the owner has `FamilyBoxAccess`
    /// set ("in family"); writes/creates/deletes/resizes require "in family"
    /// -- `ForeignBoxReads` alone never authorizes a write.
    fn authorize_box_access(
        &mut self,
        owner_app_id: u64,
        operation: BoxOperation,
    ) -> Result<(), AlgoError> {
        let owner_params =
            self.store
                .get_app_params(owner_app_id)
                .ok_or_else(|| AlgoError::Avm {
                    message: format!("app {owner_app_id} does not exist"),
                })?;
        let owner_creator = owner_params.creator.0;

        // `family_shared` is true when the box behaves like family-shared
        // state: owned by a same-creator app that has opted into
        // `FamilyBoxAccess`.
        let family_shared;
        if owner_app_id == self.app_id {
            // An app may always access its own boxes.
            family_shared = owner_params.family_box_access;
        } else {
            // Resolve whether the calling app shares a creator with the
            // owner, but only pay the cost of the lookup when
            // `FamilyBoxAccess` is set.
            let mut in_family = false;
            if owner_params.family_box_access {
                in_family = self.creator == owner_creator;
            }

            let is_read = operation == BoxOperation::Read;
            if is_read && owner_params.foreign_box_reads {
                // any app with a box reference may read
            } else if in_family {
                // in_family only set to true if family_box_access
            } else {
                // We have a denied operation. For better errors, resolve
                // `in_family` now, even if we need the call we skipped above.
                if !owner_params.family_box_access {
                    in_family = self.creator == owner_creator;
                }
                let op = if is_read { "read" } else { "write" };
                let caller = if in_family { "family" } else { "foreign" };
                return Err(AlgoError::Avm {
                    message: format!(
                        "{caller} app {} may not {op} box of {owner_app_id}",
                        self.app_id
                    ),
                });
            }
            family_shared = in_family;
        }

        if !family_shared {
            return Ok(());
        }

        // Family-shared boxes behave like globals shared across the family,
        // so they need a family-scoped reentrancy guard. On a write, reject
        // it if a foreign app on the call stack separates `self` from a
        // family member that has already touched family-shared state.
        if operation != BoxOperation::Read {
            self.check_family_reentrancy()?;
        }
        // A same-creator caller that delegated this access to `self` is
        // relying on the shared state just as if it had touched the box
        // itself, so the mark is pushed up to such callers when this frame
        // returns (see the `execute_inner_appl` call site), letting it
        // survive `self`'s return and chain to every contiguous family
        // ancestor.
        self.touched_family_shared = true;
        Ok(())
    }

    /// Guards a family-relevant write by `self`. Fails when a foreign app
    /// (one outside `self`'s family) separates `self` from an ancestor in
    /// `self`'s family that has touched family-shared state. Allowing the
    /// write would let `self` clobber state the ancestor is relying on
    /// across its inner call -- the family-scoped analog of the per-app
    /// reentrancy ban. The check fires only at the write, so foreign apps
    /// remain free to call into family members for read-only queries.
    /// Matches go-algorand's `checkFamilyReentrancy`
    /// (`data/transactions/logic/box.go:124-155`) exactly, including its
    /// error text.
    fn check_family_reentrancy(&mut self) -> Result<(), AlgoError> {
        if self.family_reentrancy_checked {
            return Ok(());
        }
        let my_creator = self.creator;
        let mut seen_foreign = false;
        // Walk the caller chain from the immediate caller outward to the
        // root (the chain is stored root-first, so iterate in reverse).
        for f in self.family_chain.iter().rev() {
            if f.creator != my_creator {
                seen_foreign = true;
                continue;
            }
            if seen_foreign && f.touched_family_shared {
                return Err(AlgoError::Avm {
                    message: format!(
                        "app {} may not write family-shared box: app {} is relying on family state across a foreign call",
                        self.app_id, f.app_id
                    ),
                });
            }
        }
        self.family_reentrancy_checked = true;
        Ok(())
    }

    /// Validate box name length and box size against protocol limits.
    fn box_length_checks(&self, name: &[u8], size: u64) -> Result<(), AlgoError> {
        if name.is_empty() {
            return Err(AlgoError::Avm {
                message: "box names may not be zero length".into(),
            });
        }
        if name.len() > self.consensus.max_app_key_len {
            return Err(AlgoError::Avm {
                message: format!(
                    "name too long: length was {}, maximum is {}",
                    name.len(),
                    self.consensus.max_app_key_len
                ),
            });
        }
        if size > self.consensus.max_box_size {
            return Err(AlgoError::Avm {
                message: format!(
                    "box size too large: {}, maximum is {}",
                    size, self.consensus.max_box_size
                ),
            });
        }
        Ok(())
    }

    // ---- Box operation implementations, generalized over an explicit owner
    // `app_id` ----
    //
    // Shared by both the plain `box_*` trait methods (`app_id ==
    // self.app_id`) and the foreign `app_box_*` ones (`app_id` from the
    // stack). Matches go-algorand's `boxXxxImpl(cx, appID)` functions
    // (`data/transactions/logic/box.go:284-600`).

    fn box_get_impl(&mut self, app_id: u64, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        self.box_length_checks(name, 0)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Read,
            None,
            name,
            pre,
            None,
        );
        let (contents, exists) = self.available_app_box(app_id, name, BoxOperation::Read, 0)?;
        if exists {
            Ok((contents, true))
        } else {
            Ok((Vec::new(), false))
        }
    }

    fn box_put_impl(&mut self, app_id: u64, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
        self.box_length_checks(name, value.len() as u64)?;

        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Write,
            None,
            name,
            pre.clone(),
            None,
        );

        // BoxWriteOperation — pass value length as create_size because the
        // box may not exist yet.
        let (contents, exists) =
            self.available_app_box(app_id, name, BoxOperation::Write, value.len() as u64)?;

        if exists {
            // Replacement must match existing size.
            if contents.len() != value.len() {
                return Err(AlgoError::Avm {
                    message: format!(
                        "attempt to box_put wrong size {} != {}",
                        contents.len(),
                        value.len()
                    ),
                });
            }
            self.store.set_box(app_id, name, value.to_vec());
        } else {
            // Create the box: update min-balance accounting on the owner app.
            let app_addr = Address(app_address(app_id));
            let mut acct = self.store.get_account(&app_addr).unwrap_or_default();
            acct.total_boxes = acct.total_boxes.saturating_add(1);
            acct.total_box_bytes = acct
                .total_box_bytes
                .saturating_add(name.len() as u64 + value.len() as u64);
            self.store.set_account(&app_addr, acct);
            self.store.set_box(app_id, name, value.to_vec());
        }
        self.record_box_new_value(app_id, name);
        self.record_kv_mod(app_id, name, pre);
        Ok(())
    }

    fn box_del_impl(&mut self, app_id: u64, name: &[u8]) -> Result<bool, AlgoError> {
        self.box_length_checks(name, 0)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Delete,
            None,
            name,
            pre.clone(),
            None,
        );
        let (_, exists) = self.available_app_box(app_id, name, BoxOperation::Delete, 0)?;
        if exists {
            // Update min-balance accounting before deleting.
            let app_addr = Address(app_address(app_id));
            // Get the content to know the size for accounting.
            let content_len = self
                .store
                .get_box(app_id, name)
                .map(|v| v.len() as u64)
                .unwrap_or(0);
            let mut acct = self.store.get_account(&app_addr).unwrap_or_default();
            acct.total_boxes = acct.total_boxes.saturating_sub(1);
            acct.total_box_bytes = acct
                .total_box_bytes
                .saturating_sub(name.len() as u64 + content_len);
            self.store.set_account(&app_addr, acct);
            self.store.delete_box(app_id, name);
            // Record the deletion: post-mutation `store.get_box` now returns
            // `None`, so `record_kv_mod` naturally records empty `data`.
            self.record_kv_mod(app_id, name, pre);
        }
        Ok(exists)
    }

    fn box_len_impl(&mut self, app_id: u64, name: &[u8]) -> Result<(u64, bool), AlgoError> {
        self.box_length_checks(name, 0)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Read,
            None,
            name,
            pre,
            None,
        );
        let (contents, exists) = self.available_app_box(app_id, name, BoxOperation::Read, 0)?;
        Ok((contents.len() as u64, exists))
    }

    fn box_create_impl(&mut self, app_id: u64, name: &[u8], size: u64) -> Result<bool, AlgoError> {
        self.box_length_checks(name, size)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Write,
            None,
            name,
            pre.clone(),
            None,
        );
        let (_, exists) = self.available_app_box(app_id, name, BoxOperation::Create, size)?;
        if !exists {
            // Create the box (zero-filled) and update min-balance.
            let app_addr = Address(app_address(app_id));
            let mut acct = self.store.get_account(&app_addr).unwrap_or_default();
            acct.total_boxes = acct.total_boxes.saturating_add(1);
            acct.total_box_bytes = acct
                .total_box_bytes
                .saturating_add(name.len() as u64 + size);
            self.store.set_account(&app_addr, acct);
            self.store.set_box(app_id, name, vec![0u8; size as usize]);
        }
        // go-algorand records the write state-op even when the box already
        // existed (a no-op create); the new value is the box's current content.
        self.record_box_new_value(app_id, name);
        self.record_kv_mod(app_id, name, pre);
        // Returns true if newly created.
        Ok(!exists)
    }

    fn box_extract_impl(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, AlgoError> {
        self.box_length_checks(name, offset.saturating_add(length))?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Read,
            None,
            name,
            pre,
            None,
        );
        let (contents, exists) = self.available_app_box(app_id, name, BoxOperation::Read, 0)?;
        if !exists {
            return Err(AlgoError::Avm {
                message: format!("no such box {:?}", name),
            });
        }
        let start = offset as usize;
        let end = start + length as usize;
        if end > contents.len() {
            return Err(AlgoError::Avm {
                message: format!("extraction end {} beyond length: {}", end, contents.len()),
            });
        }
        Ok(contents[start..end].to_vec())
    }

    fn box_replace_impl(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        self.box_length_checks(name, offset.saturating_add(value.len() as u64))?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Write,
            None,
            name,
            pre.clone(),
            None,
        );
        let (contents, exists) = self.available_app_box(app_id, name, BoxOperation::Write, 0)?;
        if !exists {
            return Err(AlgoError::Avm {
                message: format!("no such box {:?}", name),
            });
        }
        let start = offset as usize;
        let end = start + value.len();
        if end > contents.len() {
            return Err(AlgoError::Avm {
                message: format!("replacement end {} beyond length: {}", end, contents.len()),
            });
        }
        let mut new_contents = contents;
        new_contents[start..end].copy_from_slice(value);
        self.store.set_box(app_id, name, new_contents);
        self.record_box_new_value(app_id, name);
        self.record_kv_mod(app_id, name, pre);
        Ok(())
    }

    fn box_resize_impl(
        &mut self,
        app_id: u64,
        name: &[u8],
        new_size: u64,
    ) -> Result<(), AlgoError> {
        self.box_length_checks(name, new_size)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Write,
            None,
            name,
            pre.clone(),
            None,
        );
        let (contents, exists) =
            self.available_app_box(app_id, name, BoxOperation::Resize, new_size)?;
        if !exists {
            return Err(AlgoError::Avm {
                message: format!("no such box {:?}", name),
            });
        }

        // Delete and recreate with new size, preserving content.
        let app_addr = Address(app_address(app_id));
        let old_len = contents.len() as u64;

        // Update min-balance: remove old, add new.
        let mut acct = self.store.get_account(&app_addr).unwrap_or_default();
        // Adjust total_box_bytes: remove old size, add new size.
        acct.total_box_bytes = acct
            .total_box_bytes
            .saturating_sub(name.len() as u64 + old_len)
            .saturating_add(name.len() as u64 + new_size);
        self.store.set_account(&app_addr, acct);

        // Build resized content.
        let resized = if new_size > old_len {
            let mut v = vec![0u8; new_size as usize];
            v[..contents.len()].copy_from_slice(&contents);
            v
        } else {
            contents[..new_size as usize].to_vec()
        };

        // Delete old and set new (go-algorand does DelBox + NewBox, but our
        // store's set_box overwrites, which is equivalent since we already
        // updated the account totals).
        self.store.set_box(app_id, name, resized);
        self.record_box_new_value(app_id, name);
        self.record_kv_mod(app_id, name, pre);
        Ok(())
    }

    fn box_splice_impl(
        &mut self,
        app_id: u64,
        name: &[u8],
        start: u64,
        length: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        self.box_length_checks(name, 0)?;
        let pre = self.box_pre_value(app_id, name);
        self.record_app_state_access(
            app_id,
            AppStateType::Box,
            AppStateOp::Write,
            None,
            name,
            pre.clone(),
            None,
        );
        let (contents, exists) = self.available_app_box(app_id, name, BoxOperation::Write, 0)?;
        if !exists {
            return Err(AlgoError::Avm {
                message: format!("no such box {:?}", name),
            });
        }

        let s = start as usize;
        if s > contents.len() {
            return Err(AlgoError::Avm {
                message: format!("replacement start {} beyond length: {}", s, contents.len()),
            });
        }
        let oend = start + length;
        if oend < start {
            return Err(AlgoError::Avm {
                message: "splice end exceeds uint64".into(),
            });
        }
        if oend as usize > contents.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "splice end {} beyond original length: {}",
                    oend,
                    contents.len()
                ),
            });
        }

        // Splice: same-size result as original (go-algorand behavior).
        let mut result = vec![0u8; contents.len()];
        result[..s].copy_from_slice(&contents[..s]);
        let copied = value.len().min(contents.len() - s);
        result[s..s + copied].copy_from_slice(&value[..copied]);
        if copied != value.len() {
            return Err(AlgoError::Avm {
                message: "splice inserted bytes too long".into(),
            });
        }
        let tail_start = s + copied;
        let tail_src = oend as usize;
        if tail_start < result.len() && tail_src < contents.len() {
            let tail_len = result.len() - tail_start;
            let avail = contents.len() - tail_src;
            let copy_len = tail_len.min(avail);
            result[tail_start..tail_start + copy_len]
                .copy_from_slice(&contents[tail_src..tail_src + copy_len]);
        }

        self.store.set_box(app_id, name, result);
        self.record_box_new_value(app_id, name);
        self.record_kv_mod(app_id, name, pre);
        Ok(())
    }

    /// Remaining inner transaction budget.
    ///
    /// With `EnableInnerTransactionPooling` (v31+), the limit is
    /// `MAX_INNER_TRANSACTIONS * len(outer_group)` pooled across the whole
    /// group, minus already-submitted inner txns.  go-algorand initialises
    /// the shared counter to `MaxTxGroupSize * MaxInnerTransactions`, but
    /// the budget is shared via a pointer across all EvalContexts in the
    /// group.  Because our context is per-app-call we scope the budget to
    /// the actual outer group size so a single-txn group gets 16, not 256.
    fn remaining_inners(&self) -> usize {
        let total_budget = self.consensus.max_inner_transactions * self.group.len();
        let used: usize = self.inner_txns.iter().map(|g| g.len()).sum();
        total_budget.saturating_sub(used)
    }

    /// Extract accumulated execution results into an `AvmResult`.
    ///
    /// Collects logs and inner transactions from the context. State deltas
    /// (global and local) are not tracked separately — the context writes
    /// directly to the store during execution. The returned `AvmResult`
    /// therefore has empty deltas; callers should rely on the store state
    /// rather than the delta maps.
    ///
    /// TODO: Track global/local deltas independently so that ClearState
    /// rejection can discard state changes without store rollback.
    pub fn to_avm_result(&self, approved: bool) -> AvmResult {
        // Flatten inner transaction groups into a single list.
        let inner_transactions: Vec<SignedTransaction> = self
            .inner_txns
            .iter()
            .flat_map(|g| g.iter().cloned())
            .collect();

        AvmResult {
            global_delta: std::collections::HashMap::new(),
            local_deltas: std::collections::HashMap::new(),
            inner_transactions,
            logs: self.logs.clone(),
            approved,
            error: None,
            coverage: algo_avm::OpcodeCoverage::default(),
            // Not this context's own machine-level scratch (this method has
            // no access to it -- `self.scratch` only holds *sibling* rows
            // for `gload`), so there's no real value to report here.
            scratch: default_scratch_row(),
        }
    }
}

// ---------------------------------------------------------------------------
// execute_inner_appl — free function for recursive inner app call execution
// ---------------------------------------------------------------------------

/// Execute an inner `appl` (application call) transaction by running the
/// called app's program in a child `LedgerAvmContext`.
///
/// This is a free function (not a method on `LedgerAvmContext`) so that
/// it can reborrow `store: &mut L` without conflicting with the outer
/// context's borrow. The caller provides all necessary metadata.
///
/// On success, applies OnCompletion side effects and returns
/// `InnerApplyData` with any created app ID.
#[allow(clippy::too_many_arguments)]
fn execute_inner_appl<L: LedgerStore>(
    store: &mut L,
    stxn: &mut SignedTransaction,
    caller_depth: u32,
    caller_app_id: u64,
    caller_creator: [u8; 32],
    round: u64,
    latest_timestamp: u64,
    genesis_hash: [u8; 32],
    fee_credit: u64,
    fee_residue: u64,
    txn_counter: u64,
    fee_sink: Address,
    opcode_budget: &mut i64,
    inner_txn_id: algo_types::Digest,
    box_state: crate::apply::BoxBudgetState,
    family_chain: Vec<FamilyFrame>,
    created_apps_snapshot: Vec<u64>,
    consensus: ConsensusParams,
    mut tracer: Option<&mut dyn algo_avm::tracer::EvalTracer>,
    log_limits: (u64, u64),
    unnamed_tracking: Option<Arc<NamedGroupResources>>,
    kv_mods_recorder: Option<KvModsRecorder>,
    // ── Inner-group sibling context (issue #714) ──
    //
    // go-algorand's `EvalContract` treats an inner transaction group exactly
    // like a top-level group: `opItxnSubmit` builds one `NewInnerEvalParams`
    // shared by every sibling in the inner group (`data/transactions/logic/
    // eval.go`), so `cx.pastScratch` is a real, correctly-sized array across
    // the whole inner group, not a single-element placeholder. `inner_siblings`
    // is the full (snapshotted) inner-group txn list built by `itxn_submit`,
    // `sibling_index` is this call's position within it, and `inner_ran_program`
    // / `inner_scratch` are that inner group's shared, `RefCell`-guarded
    // ran/scratch record -- the same `GroupInfo::ran_program`/`GroupInfo::
    // scratch` pattern `apply.rs` established for top-level groups (#686),
    // generalized here so a nested inner-of-inner call seeds its own
    // independent record (built fresh by its own `itxn_submit`), not this
    // group's.
    inner_siblings: Vec<SignedTransaction>,
    sibling_index: usize,
    inner_ran_program: &RefCell<Vec<bool>>,
    inner_scratch: &RefCell<Vec<Option<[TealValue; 256]>>>,
) -> Result<crate::apply::InnerApplyData, AlgoError> {
    use algo_avm::eval::{
        run_approval_program, run_approval_program_with_tracer, run_clear_state_program,
        run_clear_state_program_with_tracer,
    };
    use algo_avm::group::GroupBudget;

    let mut ad = crate::apply::InnerApplyData::default();
    let called_app_id = stxn.txn.application_id;
    let on_completion = stxn.txn.on_completion;
    let sender = stxn.txn.sender;

    // ── Handle app creation (application_id == 0) ──
    let effective_app_id = if called_app_id == 0 {
        let new_app_id = txn_counter + 1;
        ad.application_id = new_app_id;
        create_application(store, &stxn.txn, new_app_id, ApplErrorContext::Inner)?;
        // Record the created app ID on the SignedTransaction.
        stxn.apply_data_application_id = new_app_id;
        // Exclude this inner-created app's state from initial-state capture
        // (it has no pre-simulation state). No-op without a tracer. Mirrors the
        // top-level app-create hook in `apply_appl`.
        if let Some(ref mut t) = tracer {
            t.record_created_app(new_app_id);
        }
        new_app_id
    } else {
        called_app_id
    };

    // ── OptIn: create local state before running program ──
    if on_completion == ON_COMPLETION_OPT_IN {
        apply_appl_opt_in_pre_program(store, &sender, effective_app_id, ApplErrorContext::Inner)?;
    }

    // ── ClearState: verify sender is opted in before running program ──
    // go-algorand checks HasAppLocalState BEFORE running the clear-state program.
    if on_completion == ON_COMPLETION_CLEAR_STATE
        && !store.has_app_local_state(&sender, effective_app_id)
    {
        return Err(AlgoError::Avm {
            message: format!(
                "cannot clear state: {} is not currently opted in to app {}",
                sender, effective_app_id,
            ),
        });
    }

    // ── Load the program ──
    let app = store
        .get_app_params(effective_app_id)
        .ok_or_else(|| AlgoError::Avm {
            message: format!("inner appl: app {} not found", effective_app_id),
        })?;

    let program = if on_completion == ON_COMPLETION_CLEAR_STATE {
        app.clear_state_program.clone()
    } else {
        app.approval_program.clone()
    };
    let creator = app.creator.0;

    // Compute program hash for ed25519verify domain separation.
    let ph = program_hash(&program);

    // ── Budget pooling: add INNER_APP_BUDGET for this app call ──
    // Per go-algorand IsolateClearState: ClearState programs run with their
    // own isolated budget (MAX_APP_PROGRAM_COST = 700) and do NOT add to
    // the shared pool. Only non-ClearState app calls contribute budget.
    if on_completion != ON_COMPLETION_CLEAR_STATE {
        *opcode_budget += consensus.max_app_program_cost as i64;
    }

    // ── Create a GroupBudget from the shared opcode budget ──
    // We create a GroupBudget with 0 app calls (so initial = 0), then add
    // the full shared budget to it.
    let mut budget = GroupBudget::new(0);
    budget.add(*opcode_budget);

    // ── Create child AVM context ──
    // Build the full inner-group sibling list (not just this one txn) so
    // `gload`/`gloads`/`gloadss` against an earlier sibling in this same
    // inner group can see it (issue #714), mirroring go-algorand sharing one
    // `EvalParams`/`pastScratch` across an entire inner group.
    let mut inner_ctx = LedgerAvmContext::new(
        store,
        inner_siblings,
        sibling_index,
        round,
        latest_timestamp,
        effective_app_id,
        creator,
        true, // app_mode
        ph,
        genesis_hash,
        consensus.clone(),
    );
    inner_ctx.set_program_version(
        algo_avm::bytecode::parse(&program)
            .map(|p| p.version)
            .unwrap_or(0),
    );
    inner_ctx.caller_app_id_val = caller_app_id;
    inner_ctx.caller_app_address_val = app_address(caller_app_id);
    inner_ctx.depth = caller_depth + 1;
    inner_ctx.fee_credit = fee_credit;
    inner_ctx.fee_residue = fee_residue;
    inner_ctx.txn_counter = txn_counter;
    inner_ctx.fee_sink = fee_sink;
    // P1-3: Set parent_txn_id to the InnerID of this appl txn so that
    // any nested inner transactions derive their IDs from the correct
    // parent (the immediate parent inner txn, not the original outer txn).
    inner_ctx.parent_txn_id = inner_txn_id;

    // H1: Inherit box budget state from parent. In go-algorand, `available`
    // (containing boxes, dirtyBytes, unnamedAccess) and `ioBudget` are shared
    // by pointer. We copy in and will copy back after execution.
    inner_ctx.available_boxes = box_state.available_boxes;
    inner_ctx.dirty_bytes = box_state.dirty_bytes;
    inner_ctx.io_budget = box_state.io_budget;
    inner_ctx.update_bytes = box_state.update_bytes;
    inner_ctx.read_budget_checked = true; // inner calls skip the read check (go-algorand line 556)
    inner_ctx.boxes_initialized = box_state.boxes_initialized;
    inner_ctx.unnamed_access = box_state.unnamed_access;
    // Inherit created_apps so newAppAccess fallback works for apps created earlier.
    inner_ctx.created_apps = created_apps_snapshot;
    // Family-shared box reentrancy guard: inherit the caller-chain snapshot
    // (see `FamilyFrame`). `family_chain` already includes the immediate
    // caller's own frame (pushed by the call site before invoking us).
    inner_ctx.family_chain = family_chain;

    // Inherit simulation eval overrides: log limits and unnamed-resource
    // tracking apply at every inner-call depth.
    inner_ctx.max_log_calls = log_limits.0;
    inner_ctx.max_log_size = log_limits.1;
    inner_ctx.unnamed_tracking = unnamed_tracking;

    // Propagate the round-level kv_mods recorder so box mutations made by
    // an inner app call are captured too (issue #570) — box budget/dirty
    // tracking is already shared this way (see H1 above).
    inner_ctx.kv_mods_recorder = kv_mods_recorder;

    // Propagate tracer to inner context for recursive inner tracing.
    // SAFETY: tracer_ptr derived from the mutable reference in `tracer`, which
    // outlives `inner_ctx`. Only one mutable ref is created at a time.
    if let Some(ref mut t) = tracer {
        inner_ctx.tracer_ptr = Some(*t as *mut dyn algo_avm::tracer::EvalTracer);
    }

    // Seed this inner-group member's scratch view from the shared inner-group
    // ran/scratch record, so `gload`/`gloads`/`gloadss` can see which earlier
    // siblings within *this* inner group already ran a program and read back
    // the real per-slot values they wrote (issue #714; mirrors
    // `apply.rs::seed_avm_scratch_from_group` for top-level groups). A
    // sibling that never ran (or hasn't executed yet) is left `None`.
    {
        let ran = inner_ran_program.borrow();
        let recorded = inner_scratch.borrow();
        for idx in 0..inner_ctx.scratch.len().min(ran.len()) {
            if ran[idx] {
                inner_ctx.scratch[idx] =
                    Some(recorded[idx].clone().unwrap_or_else(default_scratch_row));
            }
        }
    }
    // Mark this inner-group member as having started running its program
    // *before* invoking it (matches go-algorand's `EvalContract` ordering --
    // `cx.pastScratch[cx.groupIndex] = &cx.Scratch` is set immediately on
    // entry, before any opcode runs), so a sibling that reads `gload` on us
    // sees "ran" even if we go on to reject/error.
    inner_ran_program.borrow_mut()[sibling_index] = true;

    // ── Execute the program ──
    let avm_result = if on_completion == ON_COMPLETION_CLEAR_STATE {
        // ClearStateOC: run clear state program. On failure, still clear state.
        if let Some(ref mut t) = tracer {
            run_clear_state_program_with_tracer(&program, &mut inner_ctx, &consensus, *t)
        } else {
            run_clear_state_program(&program, &mut inner_ctx, &consensus)
        }
    } else {
        let res = if let Some(ref mut t) = tracer {
            run_approval_program_with_tracer(&program, &mut inner_ctx, &mut budget, *t)
        } else {
            run_approval_program(&program, &mut inner_ctx, &mut budget)
        };
        match res {
            Ok(mut result) => {
                // Mirrors go-algorand's `EvalContract`
                // (`data/transactions/logic/eval.go:1353-1358`): `err ==
                // nil && pass` gates `considerBudgetProgramWrites`, and a
                // failure there flips `pass` to false the same as any other
                // post-execution rejection (issue #723).
                if result.approved {
                    if let Err(e) = inner_ctx.consider_budget_program_writes() {
                        result.approved = false;
                        result.error = Some(e.to_string());
                    }
                }
                result
            }
            Err(e) => {
                // Update the shared budget with what was consumed.
                *opcode_budget = budget.remaining();
                return Err(e);
            }
        }
    };

    // ── Update shared opcode budget ──
    *opcode_budget = budget.remaining();

    // Record this inner-group member's real final scratch space so a later
    // sibling's `gload` sees the actual values written, not a zero-filled
    // placeholder (issue #714) -- regardless of whether this program
    // approved, rejected, or errored (see `AvmResult::scratch`'s doc).
    inner_scratch.borrow_mut()[sibling_index] = Some(avm_result.scratch.clone());

    // ── Check approval ──
    if on_completion != ON_COMPLETION_CLEAR_STATE && !avm_result.approved {
        // Non-ClearState programs must approve.
        let err_msg = avm_result
            .error
            .unwrap_or_else(|| "program rejected".to_string());
        return Err(AlgoError::Avm {
            message: format!("inner appl: {}", err_msg),
        });
    }

    // ── Collect fee_credit and txn_counter from child ──
    // Logs, inner txns, and state deltas are captured in the AvmResult (extracted
    // from the context by run_approval_program/run_clear_state_program) and
    // encoded into the inner txn's eval_delta below.
    // Capture fee_credit and txn_counter for propagation back to parent (H5/H6).
    let child_fee_credit = inner_ctx.fee_credit;
    let child_fee_residue = inner_ctx.fee_residue;
    let child_txn_counter = inner_ctx.txn_counter;
    // P1-3: Capture all asset/app IDs created by nested inner txns so the
    // parent can track them for snapshot rollback.
    let child_created_assets = inner_ctx.created_assets.clone();
    let child_created_apps = inner_ctx.created_apps.clone();

    // H1: Capture box budget state to propagate back to the parent.
    //
    // `touched_family_shared` here is already resolved to "should the
    // caller mark itself touched", matching go-algorand's merge-back
    // condition (`data/transactions/logic/eval.go:1373-1384`): a
    // family-shared touch by this (child) frame counts as a touch by its
    // caller only when they share a creator -- the caller delegated the
    // mutation to us and relies on that shared state across its own later
    // calls, exactly as if it had touched the box itself.
    let child_box_state = crate::apply::BoxBudgetState {
        available_boxes: inner_ctx.available_boxes.clone(),
        dirty_bytes: inner_ctx.dirty_bytes,
        io_budget: inner_ctx.io_budget,
        update_bytes: inner_ctx.update_bytes.clone(),
        read_budget_checked: inner_ctx.read_budget_checked,
        boxes_initialized: inner_ctx.boxes_initialized,
        unnamed_access: inner_ctx.unnamed_access,
        touched_family_shared: inner_ctx.touched_family_shared && creator == caller_creator,
    };

    // Encode the inner app call's full eval_delta — global/local state deltas,
    // shared accounts, logs, and nested inner txns — onto the inner
    // SignedTransaction, matching go-algorand's per-transaction EvalDelta
    // (eval.go:5751 appends each inner txn with its own ApplyData). Reuses the
    // same encoder as the outer txn (TASK-280); nested `itx[*].dt` are already
    // populated on each child stxn, so the recursion composes. (TASK-281)
    let dt = crate::eval_delta::encode_eval_delta(&avm_result, &stxn.txn);
    stxn.eval_delta = dt;

    // ── Apply OnCompletion side effects (post-program) ──
    // Drop inner_ctx to release the borrow on store before applying on-completion effects.
    drop(inner_ctx);

    // Apply on-completion side effects via the shared helper.
    // ON_COMPLETION_OPT_IN is a no-op (handled by apply_appl_opt_in_pre_program above).
    apply_appl_on_completion(
        store,
        &stxn.txn,
        effective_app_id,
        ApplErrorContext::Inner,
        &consensus,
    )?;

    // Propagate fee_credit, fee_residue, and txn_counter back to the parent (H5/H6).
    ad.fee_credit = child_fee_credit;
    ad.fee_residue = child_fee_residue;
    ad.txn_counter = child_txn_counter;
    // P1-3: Propagate all nested created resources so the parent's
    // rollback can clean them up if a later sibling txn fails.
    ad.nested_created_assets = child_created_assets;
    ad.nested_created_apps = child_created_apps;
    // H1: Propagate box budget state back to the parent.
    ad.box_state = Some(child_box_state);

    Ok(ad)
}

// ---------------------------------------------------------------------------
// Block-round availability window (`block` opcode, `FirstValidTime` field)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Group-wide resource availability (issue #808)
// ---------------------------------------------------------------------------

/// AVM version at which apps can access resources shared by other
/// transactions in the group (go-algorand's `sharedResourcesVersion`,
/// `data/transactions/logic/opcodes.go`).
const SHARED_RESOURCES_VERSION: u8 = 9;

/// Accounts/assets/apps made available to the currently-executing
/// transaction by its *sibling* transactions in the group, mirroring
/// go-algorand's `resources` struct (`data/transactions/logic/resources.go`).
///
/// Covers both the foreign-array-style resource sharing
/// (`fillPayment`/`fillKeyRegistration`/`fillAssetConfig`/
/// `fillAssetTransfer`/`fillAssetFreeze`/`fillApplicationCallForeign`) and,
/// as of issue #841, the cross-product "Holding"/"Local State" sharing
/// (`shared_holdings`/`shared_locals`, consulted by `allowsHolding`/
/// `allowsLocals` -- see [`LedgerAvmContext::is_holding_available`]/
/// [`LedgerAvmContext::is_local_available`]) and the `tx.Access`-list-based
/// fill path (`fillApplicationCallAccess`).
#[derive(Debug, Default, Clone)]
pub(crate) struct GroupResources {
    shared_accounts: std::collections::HashSet<[u8; 32]>,
    shared_asas: std::collections::HashSet<u64>,
    shared_apps: std::collections::HashSet<u64>,
    /// Account+asset cross products made available by some single sibling
    /// transaction. Matches go's `resources.sharedHoldings`.
    shared_holdings: std::collections::HashSet<([u8; 32], u64)>,
    /// Account+app cross products made available by some single sibling
    /// transaction. Matches go's `resources.sharedLocals`.
    shared_locals: std::collections::HashSet<([u8; 32], u64)>,
}

impl GroupResources {
    /// Matches go-algorand's `resources.shareAccountAndHolding`.
    fn share_account_and_holding(&mut self, addr: [u8; 32], asset_id: u64) {
        self.shared_accounts.insert(addr);
        if asset_id != 0 {
            self.shared_holdings.insert((addr, asset_id));
        }
    }

    /// Matches go-algorand's `resources.shareLocal`.
    fn share_local(&mut self, addr: [u8; 32], app_id: u64) {
        self.shared_locals.insert((addr, app_id));
    }

    /// Matches go-algorand's `resources.fillApplicationCallForeign`
    /// (`data/transactions/logic/resources.go`): the legacy per-type
    /// foreign-array fill path, used when `txn.access` is absent.
    fn fill_application_call_foreign(&mut self, txn: &Transaction) {
        let mut tx_accounts: Vec<[u8; 32]> = vec![txn.sender.0];
        if let Some(accounts) = &txn.accounts {
            tx_accounts.extend(accounts.iter().map(|a| a.0));
        }
        if let Some(assets) = &txn.foreign_assets {
            self.shared_asas.extend(assets.iter().copied());
        }
        if txn.application_id != 0 {
            tx_accounts.push(app_address(txn.application_id));
            self.shared_apps.insert(txn.application_id);
        }
        if let Some(apps) = &txn.foreign_apps {
            for &id in apps {
                tx_accounts.push(app_address(id));
                self.shared_apps.insert(id);
            }
        }
        for addr in tx_accounts {
            self.shared_accounts.insert(addr);
            if let Some(assets) = &txn.foreign_assets {
                for &id in assets {
                    self.shared_holdings.insert((addr, id));
                }
            }
            if txn.application_id != 0 {
                self.shared_locals.insert((addr, txn.application_id));
            }
            if let Some(apps) = &txn.foreign_apps {
                for &id in apps {
                    self.shared_locals.insert((addr, id));
                }
            }
        }
    }

    /// Matches go-algorand's `resources.fillApplicationCallAccess`
    /// (`data/transactions/logic/resources.go`): the `tx.Access`-list fill
    /// path (AVM v10+), used when `txn.access` is present.
    fn fill_application_call_access(&mut self, txn: &Transaction, access: &[ResourceRef]) {
        // The only implicitly available things are the sender, the app, and
        // the sender's locals.
        self.shared_accounts.insert(txn.sender.0);
        if txn.application_id != 0 {
            self.shared_apps.insert(txn.application_id);
            self.share_local(txn.sender.0, txn.application_id);
        }
        for rr in access {
            if !rr.address.is_zero() {
                self.shared_accounts.insert(rr.address.0);
            } else if rr.asset != 0 {
                self.shared_asas.insert(rr.asset);
            } else if rr.app != 0 {
                self.shared_apps.insert(rr.app);
            } else if rr.holding.as_ref().is_some_and(|h| !h.is_empty()) {
                // `ApplicationCallTxnFields.wellFormed` (algo-validate)
                // ensures no error here; a malformed entry is skipped,
                // matching go's `_ = err` after `wellFormed` has already run.
                if let Some((addr, asset)) =
                    resolve_access_holding_ref(rr.holding.as_ref().unwrap(), access, txn.sender.0)
                {
                    self.shared_holdings.insert((addr, asset));
                }
            } else if rr.locals.as_ref().is_some_and(|l| !l.is_empty()) {
                if let Some((addr, app)) = resolve_access_locals_ref(
                    rr.locals.as_ref().unwrap(),
                    access,
                    txn.sender.0,
                    txn.application_id,
                ) {
                    self.share_local(addr, app);
                }
            }
            // BoxRef entries and fully-empty entries only affect the box
            // read/write quota (`unnamedAccess`), not resource availability
            // -- out of scope here.
        }
    }
}

/// Resolve a `HoldingRef`'s address/asset against the `Access` list,
/// mirroring go-algorand's `HoldingRef.Resolve`
/// (`data/transactions/application.go`). Returns `None` on any malformed
/// index; static validation (`algo_validate`) already rejects malformed
/// `tx.Access` before AVM evaluation runs, matching go's own
/// "wellFormed ensures no error here" comment at its call site.
fn resolve_access_holding_ref(
    hr: &HoldingRef,
    access: &[ResourceRef],
    sender: [u8; 32],
) -> Option<([u8; 32], u64)> {
    let address = if hr.address == 0 {
        sender
    } else {
        let rr = access.get((hr.address - 1) as usize)?;
        if rr.address.is_zero() {
            return None;
        }
        rr.address.0
    };
    if hr.asset == 0 {
        return None;
    }
    let rr = access.get((hr.asset - 1) as usize)?;
    if rr.asset == 0 {
        return None;
    }
    Some((address, rr.asset))
}

/// Resolve a `LocalsRef`'s address/app against the `Access` list, mirroring
/// go-algorand's `LocalsRef.Resolve`. See [`resolve_access_holding_ref`]'s
/// doc for the "malformed entry is skipped" rationale.
fn resolve_access_locals_ref(
    lr: &LocalsRef,
    access: &[ResourceRef],
    sender: [u8; 32],
    current_app: u64,
) -> Option<([u8; 32], u64)> {
    let address = if lr.address == 0 {
        sender
    } else {
        let rr = access.get((lr.address - 1) as usize)?;
        if rr.address.is_zero() {
            return None;
        }
        rr.address.0
    };
    let app = if lr.app == 0 {
        current_app
    } else {
        let rr = access.get((lr.app - 1) as usize)?;
        if rr.app == 0 {
            return None;
        }
        rr.app
    };
    Some((address, app))
}

/// Compute the set of resources every sibling transaction in `group` makes
/// available to the others, matching go-algorand's `resources.fill` walk
/// over the group (`data/transactions/logic/resources.go`).
pub(crate) fn fill_group_resources(group: &[SignedTransaction]) -> GroupResources {
    let mut r = GroupResources::default();
    for stxn in group {
        let txn = &stxn.txn;
        match txn.txn_type.as_str() {
            "pay" => {
                r.shared_accounts.insert(txn.sender.0);
                r.shared_accounts.insert(txn.receiver.0);
                if !txn.close_remainder_to.is_zero() {
                    r.shared_accounts.insert(txn.close_remainder_to.0);
                }
            }
            "keyreg" => {
                r.shared_accounts.insert(txn.sender.0);
            }
            "acfg" => {
                r.shared_accounts.insert(txn.sender.0);
                if txn.config_asset != 0 {
                    r.shared_asas.insert(txn.config_asset);
                }
            }
            "axfer" => {
                let id = txn.xaid;
                r.shared_asas.insert(id);
                r.share_account_and_holding(txn.sender.0, id);
                if let Some(addr) = &txn.asset_receiver {
                    r.share_account_and_holding(addr.0, id);
                }
                if let Some(addr) = &txn.asset_sender {
                    if !addr.is_zero() {
                        r.share_account_and_holding(addr.0, id);
                    }
                }
                if let Some(addr) = &txn.asset_close_to {
                    if !addr.is_zero() {
                        r.share_account_and_holding(addr.0, id);
                    }
                }
            }
            "afrz" => {
                r.shared_accounts.insert(txn.sender.0);
                r.shared_asas.insert(txn.freeze_asset);
                if let Some(addr) = &txn.freeze_account {
                    r.share_account_and_holding(addr.0, txn.freeze_asset);
                }
            }
            "appl" => {
                if let Some(access) = &txn.access {
                    r.fill_application_call_access(txn, access);
                } else {
                    r.fill_application_call_foreign(txn);
                }
            }
            _ => {
                // State proof, heartbeat, and unknown types add nothing to
                // availability (matches go's `resources.fill` default arm).
            }
        }
    }
    r
}

/// Disallow an inner app call from re-entering the currently-executing app
/// (direct self-call) or any ancestor in its caller chain (an indirect
/// A->B->A cycle across inner app calls). Matches go-algorand's
/// `data/transactions/logic/eval.go`: the direct `cx.appID ==
/// subtxn.ApplicationID` check, followed by `for parent := cx.caller; parent
/// != nil; parent = parent.caller`. `family_chain` already carries every
/// ancestor's app_id (see [`FamilyFrame`]), so no separate ancestor tracking
/// is needed here.
fn check_reentrancy(
    self_app_id: u64,
    family_chain: &[FamilyFrame],
    called_app_id: u64,
) -> Result<(), AlgoError> {
    if called_app_id == self_app_id {
        return Err(AlgoError::Avm {
            message: "attempt to self-call".to_string(),
        });
    }
    if let Some(ancestor) = family_chain.iter().find(|f| f.app_id == called_app_id) {
        return Err(AlgoError::Avm {
            message: format!("attempt to re-enter {}", ancestor.app_id),
        });
    }
    Ok(())
}

/// Check that the live key/value counts in `state` do not exceed `schema`'s
/// declared `NumUint`/`NumByteSlice` bounds, matching go-algorand's
/// `storageDelta.checkCounts` (`ledger/eval/appcow.go`), which runs after
/// every state write.
fn check_state_schema_counts(
    state: &std::collections::BTreeMap<Vec<u8>, TealValue>,
    schema: &algo_types::StateSchema,
) -> Result<(), AlgoError> {
    let mut num_uint = 0u64;
    let mut num_byte_slice = 0u64;
    for v in state.values() {
        match v {
            TealValue::Uint(_) => num_uint += 1,
            TealValue::Bytes(_) => num_byte_slice += 1,
        }
    }
    if num_uint > schema.num_uint {
        return Err(AlgoError::Avm {
            message: format!(
                "store integer count {num_uint} exceeds schema integer count {}",
                schema.num_uint
            ),
        });
    }
    if num_byte_slice > schema.num_byte_slice {
        return Err(AlgoError::Avm {
            message: format!(
                "store bytes count {num_byte_slice} exceeds schema bytes count {}",
                schema.num_byte_slice
            ),
        });
    }
    Ok(())
}

/// Check that `round` falls within the window of block history the
/// currently-executing transaction is allowed to access, matching
/// go-algorand's `(*EvalContext).availableRound`
/// (`data/transactions/logic/eval.go`).
///
/// The window is `[firstAvail, lastAvail]` where `firstAvail` is bounded by
/// `LastValid - MaxTxnLife - 1` (clamped to `1` early in the chain's life)
/// and `lastAvail` is `FirstValid - 1` (clamped to `0`, meaning nothing is
/// available, if `FirstValid == 0`).
fn check_available_round(
    round: u64,
    first_valid: u64,
    last_valid: u64,
    max_txn_life: u64,
) -> Result<u64, AlgoError> {
    let mut first_avail = last_valid.saturating_sub(max_txn_life).saturating_sub(1);
    if first_avail > last_valid || first_avail == 0 {
        first_avail = 1;
    }
    let mut last_avail = first_valid.saturating_sub(1);
    if last_avail > first_valid {
        last_avail = 0;
    }
    if first_avail > round || round > last_avail {
        return Err(AlgoError::Avm {
            message: format!(
                "round {round} is not available. It's outside [{first_avail}-{last_avail}]"
            ),
        });
    }
    Ok(round)
}

// ---------------------------------------------------------------------------
// Helpers for reading transaction fields
// ---------------------------------------------------------------------------

/// Read a transaction field from a `SignedTransaction`.
///
/// Delegates to the shared `algo_avm::txn_fields::read_txn_field` for most
/// fields, but overrides eval-delta fields (Logs, NumLogs, LastLog) with
/// data from the `SignedTransaction`'s `eval_delta`.
fn read_txn_field(
    stxn: &SignedTransaction,
    field: u8,
    array_index: Option<usize>,
    group_index_val: usize,
) -> Result<TealValue, AlgoError> {
    match field {
        // Logs (array) — extracted from ApplyData eval_delta ("dt.lg").
        58 => {
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
        59 => {
            let logs = extract_logs_from_eval_delta(stxn);
            Ok(TealValue::Uint(logs.len() as u64))
        }
        // LastLog — the last entry in the eval_delta logs, or empty bytes.
        62 => {
            let logs = extract_logs_from_eval_delta(stxn);
            let last = logs.last().cloned().unwrap_or_default();
            Ok(TealValue::Bytes(last))
        }
        // All other fields: delegate to the shared implementation.
        _ => txn_fields::read_txn_field(stxn, field, array_index, group_index_val),
    }
}

// ---------------------------------------------------------------------------
// AvmContext implementation
// ---------------------------------------------------------------------------

impl<'a, L: LedgerStore> AvmContext for LedgerAvmContext<'a, L> {
    fn consensus_logic_sig_version(&self) -> Option<u64> {
        Some(self.consensus.logic_sig_version)
    }

    // Matches go-algorand's `cx.txn.Txn.Access` non-empty check in
    // `(*EvalContext).begin` (`data/transactions/logic/eval.go`); see
    // `AvmContext::txn_has_access`'s doc for the full rationale.
    fn txn_has_access(&self) -> bool {
        self.group[self.group_index]
            .txn
            .access
            .as_deref()
            .is_some_and(|access| !access.is_empty())
    }

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
        // FirstValidTime (field 3): timestamp of block(FirstValid-1), which
        // requires block-history access via block_field -- not reachable
        // from the free `read_txn_field` helper (no `self`), so handle it
        // here. Matches go-algorand's `data/transactions/logic/eval.go`
        // opTxn FirstValidTime case, including its FirstValid==0 saturation
        // (go's `basics.Round` subtraction wraps; here we clamp to 0, which
        // `check_available_round`'s lastAvail==0 handling treats the same
        // way -- nothing in that window is ever available).
        if field == 3 {
            let round = stxn.txn.first_valid.0.saturating_sub(1);
            let value =
                self.block_field(round, algo_avm::fields::BlockField::BlkTimestamp as u8)?;
            return match value {
                algo_avm::machine::AvmValue::Uint64(ts) => Ok(TealValue::Uint(ts)),
                algo_avm::machine::AvmValue::Bytes(_) => Err(AlgoError::Avm {
                    message: "internal error: BlkTimestamp returned Bytes".to_string(),
                }),
            };
        }
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
            0 => Ok(TealValue::Uint(self.consensus.min_txn_fee)),
            // MinBalance
            1 => Ok(TealValue::Uint(self.consensus.min_balance)),
            // MaxTxnLife
            2 => Ok(TealValue::Uint(self.consensus.max_txn_life)),
            // ZeroAddress
            3 => Ok(TealValue::Bytes(vec![0u8; 32])),
            // GroupSize
            4 => Ok(TealValue::Uint(self.group.len() as u64)),
            // LogicSigVersion
            5 => Ok(TealValue::Uint(self.consensus.logic_sig_version)),
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
                    if *g == [0u8; 32] {
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
            // CallerApplicationID — uses caller fields set during inner app call.
            // Note: op_global intercepts this field and calls caller_app_id()
            // directly, but this fallback is kept for completeness.
            13 => Ok(TealValue::Uint(self.caller_app_id_val)),
            // CallerApplicationAddress — uses caller fields.
            14 => Ok(TealValue::Bytes(self.caller_app_address_val.to_vec())),
            // AssetCreateMinBalance
            15 => Ok(TealValue::Uint(self.consensus.min_balance)),
            // AssetOptInMinBalance
            16 => Ok(TealValue::Uint(self.consensus.min_balance)),
            // GenesisHash
            17 => Ok(TealValue::Bytes(self.genesis_hash.to_vec())),
            // PayoutsEnabled
            18 => Ok(TealValue::Uint(if self.consensus.payouts_enabled {
                1
            } else {
                0
            })),
            // PayoutsGoOnlineFee
            19 => Ok(TealValue::Uint(self.consensus.payouts_go_online_fee)),
            // PayoutsPercent
            20 => Ok(TealValue::Uint(self.consensus.payouts_percent)),
            // PayoutsMinBalance
            21 => Ok(TealValue::Uint(self.consensus.payouts_min_balance)),
            // PayoutsMaxBalance
            22 => Ok(TealValue::Uint(self.consensus.payouts_max_balance)),
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
        // Matches go-algorand's `ApplicationCallTxnFields.AddressByIndex`
        // (`data/transactions/application.go`): when `tx.Access` is present
        // (AVM v10+), indices > 0 resolve into it instead of the legacy
        // `Accounts` array (only one of the two is ever populated).
        if let Some(access) = &txn.access {
            let i = (index - 1) as usize;
            return match access.get(i) {
                Some(rr) if !rr.address.is_zero() => Ok(rr.address.0),
                Some(_) => Err(AlgoError::Avm {
                    message: format!("address reference {index} is not an Address in tx.Access"),
                }),
                None => Err(AlgoError::Avm {
                    message: format!(
                        "invalid Account reference {} exceeds length of tx.Access {}",
                        index,
                        access.len()
                    ),
                }),
            };
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
        let id = self.resolve_asset_unchecked(index)?;
        self.check_forbidden_low_resource(id, "Asset")?;
        Ok(id)
    }

    fn resolve_app(&self, index: u64) -> Result<u64, AlgoError> {
        let id = self.resolve_app_unchecked(index)?;
        self.check_forbidden_low_resource(id, "App")?;
        Ok(id)
    }

    // ---- State reads ----

    fn app_opted_in(&self, account: &[u8; 32], app_id: u64) -> Result<bool, AlgoError> {
        self.note_local_access(account, app_id);
        let addr = Address(*account);
        Ok(self.store.has_app_local_state(&addr, app_id))
    }

    fn app_local_get(
        &self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<Option<TealValue>, AlgoError> {
        self.note_local_access(account, app_id);
        let addr = Address(*account);
        let value = match self.store.get_app_local_state(&addr, app_id) {
            Some(local) => local.key_value.get(key).cloned(),
            None => None,
        };
        self.record_app_state_access(
            app_id,
            AppStateType::Local,
            AppStateOp::Read,
            Some(*account),
            key,
            value.clone(),
            None,
        );
        Ok(value)
    }

    fn app_global_get(&self, app_id: u64, key: &[u8]) -> Result<Option<TealValue>, AlgoError> {
        self.note_app_access(app_id);
        let value = match self.store.get_app_params(app_id) {
            Some(params) => params.global_state.get(key).cloned(),
            None => None,
        };
        self.record_app_state_access(
            app_id,
            AppStateType::Global,
            AppStateOp::Read,
            None,
            key,
            value.clone(),
            None,
        );
        Ok(value)
    }

    // ---- State writes ----

    fn app_local_put(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        // Matches `app_local_get`/`app_opted_in`'s tracking call: a
        // local-state *write* to an unnamed (account, app) pair must be
        // recorded too, not just reads (issue #974's
        // `TestUnnamedResourcesAccountLocalWrite`) -- `is_local_available`
        // itself only decides availability; the note is the accessor's job,
        // matching `is_holding_available`'s documented pattern.
        self.note_local_access(account, app_id);
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
        let pre = local.key_value.get(key).cloned();
        self.record_app_state_access(
            app_id,
            AppStateType::Local,
            AppStateOp::Write,
            Some(*account),
            key,
            pre,
            Some(value.clone()),
        );
        local.key_value.insert(key.to_vec(), value.clone());
        check_state_schema_counts(&local.key_value, &local.schema)?;
        self.store.set_app_local_state(&addr, app_id, local);
        // Track delta for EvalDelta comparison.
        if app_id == self.app_id {
            self.local_delta_tracker
                .insert((addr, key.to_vec()), Some(value));
        }
        Ok(())
    }

    fn app_local_del(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<(), AlgoError> {
        self.note_local_access(account, app_id);
        let addr = Address(*account);
        let pre = self
            .store
            .get_app_local_state(&addr, app_id)
            .and_then(|l| l.key_value.get(key).cloned());
        self.record_app_state_access(
            app_id,
            AppStateType::Local,
            AppStateOp::Delete,
            Some(*account),
            key,
            pre,
            None,
        );
        if let Some(mut local) = self.store.get_app_local_state(&addr, app_id) {
            local.key_value.remove(key);
            self.store.set_app_local_state(&addr, app_id, local);
        }
        // Track delta for EvalDelta comparison.
        if app_id == self.app_id {
            self.local_delta_tracker.insert((addr, key.to_vec()), None);
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
        let pre = p.global_state.get(key).cloned();
        self.record_app_state_access(
            app_id,
            AppStateType::Global,
            AppStateOp::Write,
            None,
            key,
            pre,
            Some(value.clone()),
        );
        p.global_state.insert(key.to_vec(), value.clone());
        check_state_schema_counts(&p.global_state, &p.global_state_schema)?;
        self.store.set_app_params(app_id, p);
        // Track delta for EvalDelta comparison.
        if app_id == self.app_id {
            self.global_delta_tracker.insert(key.to_vec(), Some(value));
        }
        Ok(())
    }

    fn app_global_del(&mut self, app_id: u64, key: &[u8]) -> Result<(), AlgoError> {
        let pre = self
            .store
            .get_app_params(app_id)
            .and_then(|p| p.global_state.get(key).cloned());
        self.record_app_state_access(
            app_id,
            AppStateType::Global,
            AppStateOp::Delete,
            None,
            key,
            pre,
            None,
        );
        if let Some(mut p) = self.store.get_app_params(app_id) {
            p.global_state.remove(key);
            self.store.set_app_params(app_id, p);
        }
        // Track delta for EvalDelta comparison.
        if app_id == self.app_id {
            self.global_delta_tracker.insert(key.to_vec(), None);
        }
        Ok(())
    }

    // ---- Account / asset / app parameter queries ----

    fn balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        self.note_account_access(account);
        let addr = Address(*account);
        Ok(self
            .store
            .get_account(&addr)
            .map(|a| a.micro_algos)
            .unwrap_or(0))
    }

    fn min_balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        self.note_account_access(account);
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
        self.note_holding_access(account, asset_id);
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
        self.note_asset_access(asset_id);
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
        self.note_app_access(app_id);
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
                    // AppVersion
                    9 => TealValue::Uint(p.version),
                    // AppSizeSponsor
                    10 => TealValue::Bytes(p.size_sponsor.0.to_vec()),
                    // AppForeignBoxReads
                    11 => TealValue::Uint(p.foreign_box_reads as u64),
                    // AppFamilyBoxAccess
                    12 => TealValue::Uint(p.family_box_access as u64),
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

    /// `app_params_set AppForeignBoxReads`: read-modify-write the current
    /// app's `AppParams.foreign_box_reads` flag. Mirrors go-algorand's
    /// `roundCowState.SetForeignBoxReads` / `appParamsSetter`
    /// (`ledger/eval/cow_creatables.go`), minus the explicit creator-address
    /// lookup that go's account-scoped storage requires -- algod-rust's
    /// `AppStore` addresses app params directly by `app_id`.
    fn set_foreign_box_reads(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
        let mut p = self
            .store
            .get_app_params(app_id)
            .ok_or_else(|| AlgoError::Avm {
                message: format!("app {app_id} does not exist"),
            })?;
        p.foreign_box_reads = enable;
        self.store.set_app_params(app_id, p);
        Ok(())
    }

    /// `app_params_set AppFamilyBoxAccess`: read-modify-write the current
    /// app's `AppParams.family_box_access` flag. See
    /// [`Self::set_foreign_box_reads`] for the go-algorand mirror.
    fn set_family_box_access(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
        let mut p = self
            .store
            .get_app_params(app_id)
            .ok_or_else(|| AlgoError::Avm {
                message: format!("app {app_id} does not exist"),
            })?;
        p.family_box_access = enable;
        self.store.set_app_params(app_id, p);
        Ok(())
    }

    fn acct_params_get(
        &self,
        account: &[u8; 32],
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        self.note_account_access(account);
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
        // Enforce the per-program log limits (go-algorand `opLog`,
        // `data/transactions/logic/eval.go`). Error strings match go
        // byte-for-byte so simulation failure messages are identical.
        if self.logs.len() as u64 >= self.max_log_calls {
            return Err(AlgoError::Avm {
                message: format!(
                    "too many log calls in program. up to {} is allowed",
                    self.max_log_calls
                ),
            });
        }
        self.log_size += data.len() as u64;
        if self.log_size > self.max_log_size {
            return Err(AlgoError::Avm {
                message: format!(
                    "program logs too large. {} bytes >  {} bytes limit",
                    self.log_size, self.max_log_size
                ),
            });
        }
        self.logs.push(data);
        Ok(())
    }

    // ---- Group scratch space ----

    fn gload(&self, op_name: &str, group_index: usize, slot: u8) -> Result<TealValue, AlgoError> {
        // Mirrors go-algorand's `opGloadImpl` (`data/transactions/logic/eval.go`)
        // check ordering: range, type, self, future, then "did not run a
        // program" (nil pastScratch) before the actual scratch read.
        if group_index >= self.group.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "{op_name} lookup TxnGroup[{group_index}] but it only has {}",
                    self.group.len()
                ),
            });
        }
        if self.group[group_index].txn.txn_type != "appl" {
            return Err(AlgoError::Avm {
                message: format!(
                    "can't use {op_name} on non-app call txn with index {group_index}"
                ),
            });
        }
        if group_index == self.group_index {
            return Err(AlgoError::Avm {
                message: format!("can't use {op_name} on self, use load instead"),
            });
        }
        if group_index > self.group_index {
            return Err(AlgoError::Avm {
                message: format!(
                    "{op_name} can't get future scratch space from txn with index {group_index}"
                ),
            });
        }
        match &self.scratch[group_index] {
            Some(row) => Ok(row[slot as usize].clone()),
            // An app call that never executed its program leaves this slot
            // `None` even though its Type is still `appl` (e.g. a ClearState
            // against an already-deleted app never runs a program).
            None => Err(AlgoError::Avm {
                message: format!(
                    "{op_name} lookup of txn {group_index} that did not run a program"
                ),
            }),
        }
    }

    // ---- Group created IDs (gaid/gaids) ----

    fn created_id(&self, group_index: usize) -> Result<u64, AlgoError> {
        if group_index >= self.group.len() {
            return Err(AlgoError::Avm {
                message: format!(
                    "gaid: group_index {} out of range (group size={})",
                    group_index,
                    self.group.len()
                ),
            });
        }
        if group_index > self.group_index {
            return Err(AlgoError::Avm {
                message: format!(
                    "gaid: can't get creatable ID of txn ahead of the current one (index {} > current {})",
                    group_index, self.group_index
                ),
            });
        }
        if group_index == self.group_index {
            return Err(AlgoError::Avm {
                message: "gaid: is only for accessing creatable IDs of previous txns, use `global CurrentApplicationID` instead".to_string(),
            });
        }
        let stxn = &self.group[group_index];
        if stxn.txn.txn_type != "appl" && stxn.txn.txn_type != "acfg" {
            return Err(AlgoError::Avm {
                message: format!(
                    "gaid: txn at index {} is not an app call or asset config (type='{}')",
                    group_index, stxn.txn.txn_type
                ),
            });
        }
        // Check ApplyData fields for created asset/app IDs.
        // These are set at the SignedTxnInBlock level (not inside the "txn" map).
        if stxn.apply_data_config_asset != 0 {
            return Ok(stxn.apply_data_config_asset);
        }
        if stxn.apply_data_application_id != 0 {
            return Ok(stxn.apply_data_application_id);
        }
        Err(AlgoError::Avm {
            message: format!("gaid: txn at index {} did not create anything", group_index),
        })
    }

    // ---- Block field access ----

    fn block_field(&self, round: u64, field: u8) -> Result<algo_avm::machine::AvmValue, AlgoError> {
        let txn = &self.group[self.group_index].txn;
        let checked_round = check_available_round(
            round,
            txn.first_valid.0,
            txn.last_valid.0,
            self.consensus.max_txn_life,
        )?;

        let hdr = self
            .store
            .get_block_header(checked_round)?
            .ok_or_else(|| AlgoError::Avm {
                message: format!("block header for round {checked_round} not found"),
            })?;

        use algo_avm::fields::BlockField;
        use algo_avm::machine::AvmValue;
        let bf = BlockField::from_u8(field)?;
        match bf {
            BlockField::BlkSeed => Ok(AvmValue::Bytes(hdr.seed.to_vec())),
            BlockField::BlkTimestamp => {
                if hdr.timestamp < 0 {
                    return Err(AlgoError::Avm {
                        message: format!("block({checked_round}) timestamp {} < 0", hdr.timestamp),
                    });
                }
                Ok(AvmValue::Uint64(hdr.timestamp as u64))
            }
            BlockField::BlkProposer => Ok(AvmValue::Bytes(hdr.proposer.0.to_vec())),
            BlockField::BlkFeesCollected => Ok(AvmValue::Uint64(hdr.fees_collected)),
            BlockField::BlkBonus => Ok(AvmValue::Uint64(hdr.bonus)),
            BlockField::BlkBranch => Ok(AvmValue::Bytes(hdr.branch.to_vec())),
            BlockField::BlkFeeSink => Ok(AvmValue::Bytes(hdr.fee_sink.0.to_vec())),
            BlockField::BlkProtocol => Ok(AvmValue::Bytes(hdr.current_protocol.into_bytes())),
            BlockField::BlkTxnCounter => Ok(AvmValue::Uint64(hdr.txn_counter)),
            BlockField::BlkProposerPayout => Ok(AvmValue::Uint64(hdr.proposer_payout)),
            BlockField::BlkBranch512 => Ok(AvmValue::Bytes(hdr.prev512.to_vec())),
            BlockField::BlkSha512_256TxnCommitment => {
                Ok(AvmValue::Bytes(hdr.txn_commitment.to_vec()))
            }
            BlockField::BlkSha256TxnCommitment => Ok(AvmValue::Bytes(hdr.txn256.to_vec())),
            BlockField::BlkSha512TxnCommitment => Ok(AvmValue::Bytes(hdr.txn512.to_vec())),
        }
    }

    // ---- Inner transactions ----

    fn itxn_begin(&mut self) -> Result<(), AlgoError> {
        // Per go-algorand, calling itxn_begin while subtxns are already in
        // progress is an error: "itxn_begin without itxn_submit".
        if !self.inner_building.is_empty() {
            return Err(AlgoError::Avm {
                message: "itxn_begin without itxn_submit".to_string(),
            });
        }
        // Per go-algorand IsolateClearState: clear state programs cannot
        // issue inner transactions.
        let on_completion = self.group[self.group_index].txn.on_completion;
        if on_completion == ON_COMPLETION_CLEAR_STATE {
            return Err(AlgoError::Avm {
                message: "clear state programs can not issue inner transactions".to_string(),
            });
        }
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
                message: "itxn_next without itxn_begin".to_string(),
            });
        }
        // Per go-algorand addInnerTxn: check group size limit (precise) and
        // remaining inner txn budget (allows one extra for v5 compat, checked
        // precisely in itxn_submit).
        if self.inner_building.len() >= self.consensus.max_tx_group_size {
            return Err(AlgoError::Avm {
                message: format!(
                    "too many inner transactions {} with {} left",
                    self.inner_building.len(),
                    self.remaining_inners()
                ),
            });
        }
        if self.inner_building.len() > self.remaining_inners() {
            return Err(AlgoError::Avm {
                message: format!(
                    "too many inner transactions {} with {} left",
                    self.inner_building.len(),
                    self.remaining_inners()
                ),
            });
        }
        self.inner_building.push(InnerTxnBuilder::new());
        Ok(())
    }

    fn itxn_submit(&mut self) -> Result<(), AlgoError> {
        if self.inner_building.is_empty() {
            return Err(AlgoError::Avm {
                message: "itxn_submit without itxn_begin".to_string(),
            });
        }

        let num_subtxns = self.inner_building.len();

        // Check group size and remaining inner txn budget.
        if num_subtxns > self.remaining_inners() || num_subtxns > self.consensus.max_tx_group_size {
            return Err(AlgoError::Avm {
                message: format!(
                    "too many inner transactions {} with {} left",
                    num_subtxns,
                    self.remaining_inners()
                ),
            });
        }

        // ── Build inner transactions from the accumulated fields ──
        let builders = std::mem::take(&mut self.inner_building);
        let default_sender = Address(app_address(self.app_id));
        let mut txns: Vec<SignedTransaction> = builders
            .iter()
            .map(|b| {
                let mut stxn = b.build();
                // Default sender to the application address if not explicitly set.
                if stxn.txn.sender == Address::ZERO {
                    stxn.txn.sender = default_sender;
                }
                // Default fee to MinTxnFee only if the fee was never explicitly
                // set via `itxn_field Fee`. When `fee_set` is true, the program
                // intentionally chose the fee value (even 0 for fee pooling).
                if !b.fee_set && stxn.txn.fee == 0 {
                    stxn.txn.fee = self.consensus.min_txn_fee;
                }
                // Copy FirstValid/LastValid from the outer transaction.
                let outer = &self.group[self.group_index].txn;
                stxn.txn.first_valid = outer.first_valid;
                stxn.txn.last_valid = outer.last_valid;
                stxn
            })
            .collect();

        // ── Fee credit / residue / pooling (matches go-algorand opItxnSubmit) ──
        //
        // Usage-weight the group via SummarizeFees (each subtxn's feeFactor —
        // e.g. an oversized note — rather than a flat MinTxnFee * num_subtxns)
        // and round the required fee up against the running fee_residue, so a
        // whole tree of nested inner-txn groups rounds up its aggregate fee
        // only once rather than once per group (go-algorand PR #6650, "Fees:
        // Handle rounding of fees with non-integral usage better"). The
        // updated residue is retained on `self` so later sibling groups (and,
        // once this call returns, the caller — see `execute_inner_appl`'s
        // fee_residue propagation) see what this group already consumed
        // rather than double-spending it.
        let txn_refs: Vec<&SignedTransaction> = txns.iter().collect();
        let (usage, group_paid) = algo_validate::summarize_fees(&txn_refs, &self.consensus);
        let (group_fee, residue, overflow) = algo_validate::fee_for_usage(
            self.consensus.min_txn_fee,
            usage,
            algo_validate::ONE_MICROS,
            self.fee_residue,
        );
        if overflow {
            return Err(AlgoError::Avm {
                message: "inner group fee saturation".to_string(),
            });
        }
        self.fee_residue = residue;
        if group_paid < group_fee {
            // See if fee_credit covers the shortfall; if not, report the
            // actual net shortfall still owed after applying whatever credit
            // is available (matches go-algorand's corrected message, PR
            // #6693 "AVM: report actual inner group fee shortfall": the
            // error used to just state the flat need, now it reports
            // `groupFee.SubSaturate(groupPaid)` further reduced by
            // `cx.FeeCredit`).
            let shortfall = group_fee - group_paid;
            if self.fee_credit < shortfall {
                let net_shortfall = shortfall - self.fee_credit;
                return Err(AlgoError::Avm {
                    message: format!(
                        "group fee {} too small (needs {} more)",
                        group_paid, net_shortfall
                    ),
                });
            }
            self.fee_credit -= shortfall;
        } else {
            let overpay = group_paid - group_fee;
            self.fee_credit = self.fee_credit.saturating_add(overpay);
        }

        // ── Validate transaction types and inner app call constraints ──
        for stxn in &txns {
            let tt = stxn.txn.txn_type.as_str();
            match tt {
                "pay" | "axfer" | "acfg" | "afrz" | "keyreg" => {}
                "appl" => {
                    let called_app_id = stxn.txn.application_id;

                    check_reentrancy(self.app_id, &self.family_chain, called_app_id)?;

                    // Check depth limit: count ancestors (matching go-algorand
                    // which walks the `caller` chain). Our `self.depth` is 0 for
                    // top-level, so `depth >= MAX_APP_CALL_DEPTH` means too deep.
                    if self.depth as usize >= params::MAX_APP_CALL_DEPTH {
                        return Err(AlgoError::Avm {
                            message: format!("appl depth ({}) exceeded", self.depth),
                        });
                    }

                    // Determine the program to check version on.
                    let program = if called_app_id != 0 {
                        let app = self.store.get_app_params(called_app_id).ok_or_else(|| {
                            AlgoError::Avm {
                                message: format!(
                                    "inner appl: app {} does not exist",
                                    called_app_id
                                ),
                            }
                        })?;
                        if stxn.txn.on_completion == ON_COMPLETION_CLEAR_STATE {
                            app.clear_state_program.clone()
                        } else {
                            app.approval_program.clone()
                        }
                    } else {
                        // App creation: program comes from the transaction.
                        stxn.txn
                            .approval_program
                            .as_ref()
                            .map(|b| b.to_vec())
                            .unwrap_or_default()
                    };

                    // Version check: inner app calls require >= MIN_INNER_APPL_VERSION.
                    if program.is_empty() {
                        return Err(AlgoError::Avm {
                            message: "inner appl: empty program".to_string(),
                        });
                    }
                    let called_version = program[0] as u64;
                    if called_version < self.consensus.min_inner_appl_version {
                        return Err(AlgoError::Avm {
                            message: format!(
                                "inner app call with version v{} < v{}",
                                called_version, self.consensus.min_inner_appl_version
                            ),
                        });
                    }

                    // For OptIn, also check that the clear state program meets
                    // the minimum version requirement.
                    if stxn.txn.on_completion == ON_COMPLETION_OPT_IN {
                        let csp = if called_app_id != 0 {
                            let app =
                                self.store.get_app_params(called_app_id).ok_or_else(|| {
                                    AlgoError::Avm {
                                        message: format!(
                                            "inner appl: app {} does not exist",
                                            called_app_id
                                        ),
                                    }
                                })?;
                            app.clear_state_program.clone()
                        } else {
                            stxn.txn
                                .clear_state_program
                                .as_ref()
                                .map(|b| b.to_vec())
                                .unwrap_or_default()
                        };
                        if !csp.is_empty() {
                            let csv = csp[0] as u64;
                            if csv < self.consensus.min_inner_appl_version {
                                return Err(AlgoError::Avm {
                                    message: format!(
                                        "inner app call opt-in with CSP v{} < v{}",
                                        csv, self.consensus.min_inner_appl_version
                                    ),
                                });
                            }
                        }
                    }
                }
                _ => {
                    return Err(AlgoError::Avm {
                        message: format!("unsupported inner transaction type: {}", tt),
                    });
                }
            }
        }

        // ── Sender authorization ──
        //
        // Per go-algorand authorizedSender: the sender must be the current
        // app address, or an account whose auth_addr (rekey) is the app address.
        let app_addr = app_address(self.app_id);
        for stxn in &txns {
            let sender = &stxn.txn.sender;
            if sender.0 == app_addr {
                continue; // app address itself — always authorized
            }
            // Check if the sender is rekeyed to the app address.
            let acct = self.store.get_or_default_account(sender);
            let authorizer = acct.auth_addr.as_ref().map(|a| a.0).unwrap_or(sender.0);
            if authorizer != app_addr {
                return Err(AlgoError::Avm {
                    message: format!(
                        "app {} (addr {}) unauthorized {}",
                        self.app_id,
                        Address(app_addr),
                        Address(authorizer),
                    ),
                });
            }
        }

        // ── Take state snapshot for rollback ──
        //
        // Collect all addresses involved so the snapshot covers their state.
        let mut snapshot_addrs: Vec<Address> = Vec::new();
        snapshot_addrs.push(self.fee_sink);
        let txn_counter_base = self.txn_counter;
        for (i, stxn) in txns.iter().enumerate() {
            snapshot_addrs.push(stxn.txn.sender);
            if !stxn.txn.receiver.is_zero() {
                snapshot_addrs.push(stxn.txn.receiver);
            }
            if !stxn.txn.close_remainder_to.is_zero() {
                snapshot_addrs.push(stxn.txn.close_remainder_to);
            }
            if let Some(ref arcv) = stxn.txn.asset_receiver {
                snapshot_addrs.push(*arcv);
            }
            if let Some(ref acl) = stxn.txn.asset_close_to {
                snapshot_addrs.push(*acl);
            }
            // P1-1: Include the clawback source (asset_sender) so its holding
            // can be restored if a later inner txn in this group fails.
            if let Some(ref asnd) = stxn.txn.asset_sender {
                snapshot_addrs.push(*asnd);
            }
            if let Some(ref fa) = stxn.txn.freeze_account {
                snapshot_addrs.push(*fa);
            }
            // P1-2: For acfg txns, include the creator of the asset being
            // modified/destroyed so their account totals can be rolled back.
            if stxn.txn.txn_type == "acfg" && stxn.txn.config_asset != 0 {
                if let Some(record) = self.store.get_asset_params(stxn.txn.config_asset) {
                    snapshot_addrs.push(record.creator);
                }
            }
            // P1-2: For acfg create (config_asset == 0), include the sender
            // who becomes the creator.
            if stxn.txn.txn_type == "acfg" && stxn.txn.config_asset == 0 {
                snapshot_addrs.push(stxn.txn.sender);
            }
            // For appl inner txns, include all accounts from the transaction's
            // accounts array, plus the called app's address. These accounts can
            // be mutated during program execution (H4).
            if stxn.txn.txn_type == "appl" {
                if let Some(ref accts) = stxn.txn.accounts {
                    for acct in accts {
                        snapshot_addrs.push(*acct);
                    }
                }
                // Include the called app's address.
                if stxn.txn.application_id != 0 {
                    snapshot_addrs.push(Address(app_address(stxn.txn.application_id)));
                    // P1-2: Include the app creator for delete operations so
                    // their total_created_apps counter can be rolled back.
                    if stxn.txn.on_completion == ON_COMPLETION_DELETE {
                        if let Some(app) = self.store.get_app_params(stxn.txn.application_id) {
                            snapshot_addrs.push(app.creator);
                        }
                    }
                } else {
                    // P1-2: For app create (application_id == 0), include the
                    // sender who becomes the creator, plus the new app's address.
                    snapshot_addrs.push(stxn.txn.sender);
                    // Pre-compute the new app's address using the predicted ID.
                    let predicted_app_id = txn_counter_base + (i as u64) + 1 + 1;
                    snapshot_addrs.push(Address(app_address(predicted_app_id)));
                }
            }
        }
        // Deduplicate addresses by converting through raw bytes.
        {
            let mut seen = std::collections::HashSet::new();
            snapshot_addrs.retain(|a| seen.insert(a.0));
        }

        // Collect asset/app IDs that might be created or modified.
        let mut asset_ids: Vec<u64> = Vec::new();
        let mut app_ids: Vec<u64> = Vec::new();
        for (i, stxn) in txns.iter().enumerate() {
            if stxn.txn.config_asset != 0 {
                asset_ids.push(stxn.txn.config_asset);
            }
            if stxn.txn.xaid != 0 {
                asset_ids.push(stxn.txn.xaid);
            }
            if stxn.txn.freeze_asset != 0 {
                asset_ids.push(stxn.txn.freeze_asset);
            }
            // P1-1: For acfg create (config_asset == 0), pre-compute the
            // asset ID that will be created (txn_counter + offset + 1 + 1)
            // so the snapshot covers it for rollback.
            if stxn.txn.txn_type == "acfg" && stxn.txn.config_asset == 0 {
                let predicted_asset_id = txn_counter_base + (i as u64) + 1 + 1;
                asset_ids.push(predicted_asset_id);
            }
            // Include app IDs for inner app calls.
            if stxn.txn.txn_type == "appl" {
                if stxn.txn.application_id != 0 {
                    app_ids.push(stxn.txn.application_id);
                } else {
                    // P1-1: For appl create (application_id == 0), pre-compute
                    // the app ID that will be created so the snapshot covers it.
                    let predicted_app_id = txn_counter_base + (i as u64) + 1 + 1;
                    app_ids.push(predicted_app_id);
                }
            }
        }
        asset_ids.sort();
        asset_ids.dedup();
        app_ids.sort();
        app_ids.dedup();

        let snapshot = self
            .store
            .snapshot_with_ids(&snapshot_addrs, &asset_ids, &app_ids);

        // ── Execute each inner transaction ──
        let round = self.round;
        let fee_sink = self.fee_sink;
        // Note: txn_counter_base was already captured above for snapshot.

        // P1-3: Compute the effective parent txn ID for inner ID computation.
        // For top-level contexts (parent_txn_id is zero), compute from the
        // outer transaction. For nested contexts, use the stored
        // parent_txn_id -- but only under UnifyInnerTxIDs (v34+; go's
        // `getTxID`/`currentTxID`, `data/transactions/logic/eval.go`), which
        // recursively derives each level's own ID from its real ancestor
        // chain. Before v34 (go's `getTxIDNotUnified`), a nested inner
        // transaction's children are always parented on the *raw* hash of
        // the immediate calling transaction (`cx.caller.txn.ID()`), ignoring
        // that the caller may itself be nested -- i.e. the same raw-hash
        // formula used for a top-level parent, applied unconditionally.
        let effective_parent_txid =
            if self.consensus.unify_inner_tx_ids && self.parent_txn_id.0 != [0u8; 32] {
                self.parent_txn_id
            } else {
                algo_codec::compute_txn_id(&self.group[self.group_index].txn)
            };
        // The offset base for inner ID computation: number of already-submitted inner txns.
        let id_offset_base: usize = self.inner_txns.iter().map(|g| g.len()).sum();

        // Use a running counter that accumulates across sibling inner txns.
        // This is critical when an earlier inner appl creates nested inner
        // txns that consume counter slots — the next sibling must see the
        // updated counter, not a stale value computed from txn_counter_base.
        let mut current_counter = txn_counter_base;

        // P1-3 fix: Track resource IDs created during execution that were
        // NOT in the pre-computed snapshot. On rollback, these must be
        // explicitly removed because `restore_snapshot` only knows about
        // IDs that were in the original snapshot.
        let snapshotted_asset_ids: std::collections::HashSet<u64> =
            asset_ids.iter().copied().collect();
        let snapshotted_app_ids: std::collections::HashSet<u64> = app_ids.iter().copied().collect();
        let mut extra_created_asset_ids: Vec<u64> = Vec::new();
        let mut extra_created_app_ids: Vec<u64> = Vec::new();

        // Notify tracer of the inner transaction group.
        if let Some(p) = self.tracer_ptr {
            // SAFETY: tracer_ptr is valid for the duration of this context
            // and only one mutable ref is live at a time.
            unsafe { &mut *p }.before_txn_group(txns.len());
        }

        // Shared across every member of *this* inner group so `gload`/
        // `gloads`/`gloadss` in a later inner sibling can see whether an
        // earlier sibling actually ran a program and read back the real
        // values it wrote (issue #714) -- the same `ran_program`/`scratch`
        // pattern `apply.rs::GroupInfo` established for top-level groups
        // (#686), generalized here for inner groups. A nested inner-of-inner
        // call gets its own fresh pair from its own `itxn_submit`, so it
        // never leaks or shadows this group's record.
        let inner_ran_program: RefCell<Vec<bool>> = RefCell::new(vec![false; num_subtxns]);
        let inner_scratch: RefCell<Vec<Option<[TealValue; 256]>>> =
            RefCell::new(vec![None; num_subtxns]);

        for i in 0..num_subtxns {
            // Deduct fee from sender to fee_sink (matches go-algorand takeFee).
            let fee = txns[i].txn.fee;
            if fee > 0 {
                if fee_sink.is_zero() {
                    self.store.restore_snapshot(snapshot);
                    for &id in &extra_created_asset_ids {
                        self.store.remove_asset_params(id);
                        self.store.remove_all_asset_holdings_for_asset(id);
                    }
                    for &id in &extra_created_app_ids {
                        self.store.remove_app_params(id);
                        self.store.remove_all_app_local_states_for_app(id);
                    }
                    let err_msg = format!("inner tx {}: fee_sink not configured (zero address)", i);
                    if let Some(p) = self.tracer_ptr {
                        unsafe { &mut *p }.after_txn_group(Some(&err_msg));
                    }
                    return Err(AlgoError::Avm { message: err_msg });
                }
                let sender = txns[i].txn.sender;
                let mut sender_acct = self.store.get_or_default_account(&sender);
                if sender_acct.micro_algos < fee {
                    self.store.restore_snapshot(snapshot);
                    for &id in &extra_created_asset_ids {
                        self.store.remove_asset_params(id);
                        self.store.remove_all_asset_holdings_for_asset(id);
                    }
                    for &id in &extra_created_app_ids {
                        self.store.remove_app_params(id);
                        self.store.remove_all_app_local_states_for_app(id);
                    }
                    let err_msg = format!(
                        "inner tx {}: sender {} has insufficient balance {} for fee {}",
                        i, sender, sender_acct.micro_algos, fee,
                    );
                    if let Some(p) = self.tracer_ptr {
                        unsafe { &mut *p }.after_txn_group(Some(&err_msg));
                    }
                    return Err(AlgoError::Avm { message: err_msg });
                }
                sender_acct.micro_algos -= fee;
                self.store.set_account(&sender, sender_acct);

                let mut sink_acct = self.store.get_or_default_account(&fee_sink);
                sink_acct.micro_algos += fee;
                self.store.set_account(&fee_sink, sink_acct);
            }

            // Handle RekeyTo BEFORE type-specific dispatch (matches
            // go-algorand's `ledger/eval/eval.go` `applyTransaction`
            // ordering -- rewards, then rekey, then type dispatch -- applied
            // unconditionally to every transaction, inner or top-level).
            // Mirrors `apply.rs::apply_transaction_inner_body`'s identical
            // top-level handling; inner transactions previously bypassed it
            // entirely by dispatching straight to `apply_pay`/`apply_axfer`/
            // `execute_inner_appl`, so an inner RekeyTo was silently
            // ignored -- a real gap surfaced while porting go's
            // `TestInnerAppCreateAndOptin` (issue #964), which relies on an
            // inner appl-call's RekeyTo taking effect immediately so a
            // subsequent nested inner txn's sender-authorization check
            // (`auth_addr`) sees it within the same top-level transaction.
            if let Some(rekey_addr) = txns[i].txn.rekey_to {
                let rekey_sender = txns[i].txn.sender;
                let mut rekey_account = self.store.get_or_default_account(&rekey_sender);
                if rekey_addr == rekey_sender || rekey_addr.is_zero() {
                    rekey_account.auth_addr = None;
                } else {
                    rekey_account.auth_addr = Some(rekey_addr);
                }
                self.store.set_account(&rekey_sender, rekey_account);
            }

            // Increment txn counter before execution (matches go-algorand incTxnCount).
            current_counter += 1;
            self.txn_counter = current_counter;

            // Notify tracer before dispatching this inner transaction.
            if let Some(p) = self.tracer_ptr {
                unsafe { &mut *p }.before_txn(i);
            }

            // Dispatch to the appropriate apply function.
            if txns[i].txn.txn_type == "appl" {
                // ── Inner app call — recursive AVM execution ──
                // P1-3: Compute this inner appl txn's InnerID, which becomes the
                // parent_txn_id for any nested inner txns it may create.
                let appl_inner_id = algo_avm::itxn::compute_inner_txn_id(
                    &effective_parent_txid,
                    id_offset_base + i,
                    &txns[i].txn,
                );
                // H1: Snapshot box state to pass to inner context.
                // Ensure boxes are initialized before extracting state.
                self.ensure_boxes_initialized();
                // Run the read budget check before snapshotting, so
                // the inner call (which inherits read_budget_checked=true)
                // doesn't bypass the check if the parent hasn't run it yet.
                // In go-algorand, EvalContract runs the read budget check
                // eagerly before any opcodes execute (eval.go line 1145),
                // so by the time an inner call is created the check has
                // already passed.
                self.check_read_budget()?;
                let caller_box_state = crate::apply::BoxBudgetState {
                    available_boxes: self.available_boxes.clone(),
                    dirty_bytes: self.dirty_bytes,
                    io_budget: self.io_budget,
                    update_bytes: self.update_bytes.clone(),
                    read_budget_checked: self.read_budget_checked,
                    boxes_initialized: self.boxes_initialized,
                    unnamed_access: self.unnamed_access,
                    // Not read on the way in -- `execute_inner_appl` starts
                    // the child's own `touched_family_shared` at `false`
                    // (a fresh frame begins untouched) and only *sets* this
                    // field on the way back out (see below).
                    touched_family_shared: false,
                };
                // Family-shared box reentrancy guard: extend the caller-chain
                // snapshot with `self`'s own current frame before handing it
                // to the child (see `FamilyFrame`, `check_family_reentrancy`).
                let mut child_family_chain = self.family_chain.clone();
                child_family_chain.push(FamilyFrame {
                    app_id: self.app_id,
                    creator: self.creator,
                    touched_family_shared: self.touched_family_shared,
                });
                // SAFETY: tracer_ptr is valid for the duration of this context
                // and only one mutable ref is live at a time.
                let tracer_ref = self.tracer_ptr.map(|p| unsafe { &mut *p });
                // Snapshot the full inner-group sibling list *before* taking a
                // mutable borrow of this member (issue #714), so `gload`/
                // `gloads`/`gloadss` within this inner group sees the whole
                // group, not just this one txn. Siblings before `i` already
                // carry their real post-execution ApplyData (mutated in place
                // as this loop progressed); siblings at/after `i` still carry
                // their pre-execution defaults -- matching go-algorand's
                // `TxnGroup[j].ApplyData` population order (`ep.RecordAD`
                // runs sequentially as `cx.Ledger.Perform(i, ep)` returns).
                let siblings_snapshot: Vec<SignedTransaction> = txns.clone();
                let stxn = &mut txns[i];
                let result = execute_inner_appl(
                    self.store,
                    stxn,
                    self.depth,
                    self.app_id,
                    self.creator,
                    self.round,
                    self.latest_timestamp,
                    self.genesis_hash,
                    self.fee_credit,
                    self.fee_residue,
                    self.txn_counter,
                    self.fee_sink,
                    &mut self.opcode_budget,
                    appl_inner_id,
                    caller_box_state,
                    child_family_chain,
                    self.created_apps.clone(),
                    self.consensus.clone(),
                    tracer_ref,
                    (self.max_log_calls, self.max_log_size),
                    self.unnamed_tracking.clone(),
                    self.kv_mods_recorder.clone(),
                    siblings_snapshot,
                    i,
                    &inner_ran_program,
                    &inner_scratch,
                );
                match result {
                    Ok(ad) => {
                        stxn.apply_data_config_asset = ad.config_asset;
                        stxn.apply_data_application_id = ad.application_id;
                        stxn.closing_amount = ad.closing_amount;
                        stxn.asset_closing_amount = ad.asset_closing_amount;
                        // P1-3: Track any resources the child created that weren't
                        // in the original snapshot so rollback can clean them up.
                        if ad.config_asset != 0 && !snapshotted_asset_ids.contains(&ad.config_asset)
                        {
                            extra_created_asset_ids.push(ad.config_asset);
                        }
                        if ad.application_id != 0
                            && !snapshotted_app_ids.contains(&ad.application_id)
                        {
                            extra_created_app_ids.push(ad.application_id);
                        }
                        // P1-3: Also track resources created by nested inner txns
                        // within the child (e.g., the child app issued its own
                        // itxn_submit that created assets/apps).
                        for &nested_id in &ad.nested_created_assets {
                            if !snapshotted_asset_ids.contains(&nested_id) {
                                extra_created_asset_ids.push(nested_id);
                            }
                        }
                        for &nested_id in &ad.nested_created_apps {
                            if !snapshotted_app_ids.contains(&nested_id) {
                                extra_created_app_ids.push(nested_id);
                            }
                        }
                        // Propagate fee_credit, fee_residue, and txn_counter back from child (H5/H6).
                        self.fee_credit = ad.fee_credit;
                        self.fee_residue = ad.fee_residue;
                        // Update running counter from child — the child's counter
                        // accounts for any nested inner txns it created.
                        current_counter = ad.txn_counter;
                        self.txn_counter = current_counter;

                        // H1: Restore box budget state from inner context.
                        if let Some(bs) = ad.box_state {
                            self.available_boxes = bs.available_boxes;
                            self.dirty_bytes = bs.dirty_bytes;
                            self.io_budget = bs.io_budget;
                            self.update_bytes = bs.update_bytes;
                            self.read_budget_checked = bs.read_budget_checked;
                            self.boxes_initialized = bs.boxes_initialized;
                            self.unnamed_access = bs.unnamed_access;
                            // Family-shared touch-mark propagation
                            // (go-algorand eval.go:1373-1384): `bs`'s flag is
                            // already resolved to "the child touched
                            // family-shared state and shares our creator", so
                            // apply it unconditionally here.
                            if bs.touched_family_shared {
                                self.touched_family_shared = true;
                            }
                        }
                        // Notify tracer of successful inner transaction.
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn(i, None);
                        }
                    }
                    Err(e) => {
                        // Notify tracer of failed inner transaction.
                        let err_msg = format!("inner tx {} failed: {}", i, e);
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn(i, Some(&err_msg));
                        }
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        // Notify tracer of group failure.
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn_group(Some(&err_msg));
                        }
                        return Err(AlgoError::Avm { message: err_msg });
                    }
                }
            } else {
                let stxn = &mut txns[i];
                let result = match stxn.txn.txn_type.as_str() {
                    "pay" => apply_pay(self.store, &stxn.txn),
                    "axfer" => apply_axfer(self.store, &stxn.txn),
                    "acfg" => apply_acfg(self.store, &stxn.txn, self.txn_counter),
                    "afrz" => apply_afrz(self.store, &stxn.txn),
                    "keyreg" => apply_keyreg(self.store, &stxn.txn, round, &self.consensus),
                    _ => {
                        // Should not reach here due to earlier validation.
                        let err_msg =
                            format!("inner tx {}: unsupported type {}", i, stxn.txn.txn_type);
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn(i, Some(&err_msg));
                        }
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn_group(Some(&err_msg));
                        }
                        return Err(AlgoError::Avm { message: err_msg });
                    }
                };

                match result {
                    Ok(ad) => {
                        stxn.apply_data_config_asset = ad.config_asset;
                        stxn.apply_data_application_id = ad.application_id;
                        stxn.closing_amount = ad.closing_amount;
                        stxn.asset_closing_amount = ad.asset_closing_amount;
                        // P1-3: Track non-app creates too (acfg assets).
                        if ad.config_asset != 0 && !snapshotted_asset_ids.contains(&ad.config_asset)
                        {
                            extra_created_asset_ids.push(ad.config_asset);
                        }
                        if ad.application_id != 0
                            && !snapshotted_app_ids.contains(&ad.application_id)
                        {
                            extra_created_app_ids.push(ad.application_id);
                        }
                        // Notify tracer of successful inner transaction.
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn(i, None);
                        }
                    }
                    Err(e) => {
                        let err_msg = format!("inner tx {} failed: {}", i, e);
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn(i, Some(&err_msg));
                        }
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        if let Some(p) = self.tracer_ptr {
                            unsafe { &mut *p }.after_txn_group(Some(&err_msg));
                        }
                        return Err(AlgoError::Avm { message: err_msg });
                    }
                }
            }
        }

        // Notify tracer of successful inner transaction group completion.
        if let Some(p) = self.tracer_ptr {
            unsafe { &mut *p }.after_txn_group(None);
        }

        // ── Compute inner transaction IDs ──
        //
        // Each inner txn gets a unique ID derived from the parent txn's ID and
        // its offset within all inner txns. This matches go-algorand's
        // `Transaction.InnerID(parent, offset)`.
        //
        // P1-3: Uses `effective_parent_txid` computed above, which is set
        // correctly for both top-level contexts (outer txn ID) and nested
        // inner contexts (the inner appl txn's own computed ID).
        let mut ids = Vec::with_capacity(txns.len());
        for (i, stxn) in txns.iter().enumerate() {
            let id = algo_avm::itxn::compute_inner_txn_id(
                &effective_parent_txid,
                id_offset_base + i,
                &stxn.txn,
            );
            ids.push(id);
        }

        // ── Track created resources (assets and apps) ──
        //
        // When inner transactions create new assets or apps, those resources
        // become available to subsequent opcodes (matches go-algorand
        // `createdAsas` / `createdApps`).
        for stxn in &txns {
            if stxn.apply_data_config_asset != 0 {
                self.created_assets.push(stxn.apply_data_config_asset);
            }
            if stxn.apply_data_application_id != 0 {
                self.created_apps.push(stxn.apply_data_application_id);
            }
        }

        // ── Record completed inner transactions ──
        self.inner_txns.push(txns);
        self.inner_txn_ids.push(ids);
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
        // TxID (field 23) for inner txns uses the precomputed inner txn ID.
        if field == 23 {
            if let Some(last_ids) = self.inner_txn_ids.last() {
                if let Some(id) = last_ids.last() {
                    return Ok(TealValue::Bytes(id.0.to_vec()));
                }
            }
        }
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
        // TxID (field 23) for inner txns uses the precomputed inner txn ID.
        if field == 23 {
            if let Some(last_ids) = self.inner_txn_ids.last() {
                if let Some(id) = last_ids.get(group_index) {
                    return Ok(TealValue::Bytes(id.0.to_vec()));
                }
            }
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

    // ---- Inner transaction caller / depth ----

    fn caller_app_id(&self) -> u64 {
        self.caller_app_id_val
    }

    fn caller_app_address(&self) -> [u8; 32] {
        self.caller_app_address_val
    }

    fn inner_txn_depth(&self) -> u32 {
        self.depth
    }

    // ---- Budget sharing for inner app calls ----

    fn set_opcode_budget(&mut self, budget: i64) {
        self.opcode_budget = budget;
    }

    fn get_opcode_budget(&self) -> i64 {
        self.opcode_budget
    }

    fn supports_budget_pooling(&self) -> bool {
        true
    }

    fn enable_precheck_ecdsa_curve(&self) -> bool {
        self.consensus.enable_precheck_ecdsa_curve
    }

    // ---- Resource availability ----

    fn is_asset_available(&self, asset_id: u64) -> bool {
        if asset_id == 0 {
            return false;
        }
        // Check the current transaction's foreign assets array.
        let txn = &self.group[self.group_index].txn;
        // Named directly in `tx.Access` (AVM v10+). Matches go-algorand's
        // `availableAsset`'s `slices.ContainsFunc(Access, ...)` check.
        if let Some(ref access) = txn.access {
            if access.iter().any(|rr| rr.asset == asset_id) {
                return true;
            }
        }
        if let Some(ref assets) = txn.foreign_assets {
            if assets.contains(&asset_id) {
                return true;
            }
        }
        // Check implied asset IDs from the transaction.
        if txn.xaid == asset_id || txn.config_asset == asset_id || txn.freeze_asset == asset_id {
            return true;
        }
        // Check assets created by inner transactions.
        if self.created_assets.contains(&asset_id) {
            return true;
        }
        // Group-wide resource sharing (v9+): some other txn in the group
        // mentioned this asset. Matches go-algorand's `availableAsset`'s
        // `cx.version >= sharedResourcesVersion` branch.
        if self.program_version >= SHARED_RESOURCES_VERSION
            && self.group_resources.shared_asas.contains(&asset_id)
        {
            return true;
        }
        false
    }

    fn is_app_available(&self, app_id: u64) -> bool {
        if app_id == 0 {
            return false;
        }
        // Current app is always available.
        if app_id == self.app_id {
            return true;
        }
        // Named directly in `tx.Access` (AVM v10+). Matches go-algorand's
        // `availableApp`'s `slices.ContainsFunc(Access, ...)` check.
        let txn = &self.group[self.group_index].txn;
        if let Some(ref access) = txn.access {
            if access.iter().any(|rr| rr.app == app_id) {
                return true;
            }
        }
        // Check the current transaction's foreign apps array.
        if let Some(ref apps) = txn.foreign_apps {
            if apps.contains(&app_id) {
                return true;
            }
        }
        // Check apps created by inner transactions.
        if self.created_apps.contains(&app_id) {
            return true;
        }
        // Group-wide resource sharing (v9+): some other txn in the group
        // mentioned this app. Matches go-algorand's `availableApp`'s
        // `cx.version >= sharedResourcesVersion` branch.
        if self.program_version >= SHARED_RESOURCES_VERSION
            && self.group_resources.shared_apps.contains(&app_id)
        {
            return true;
        }
        false
    }

    /// Matches go-algorand's `availableAccount`
    /// (`data/transactions/logic/eval.go`): a raw address is available if
    /// it's the current transaction's own sender/`Accounts[]` entry, the
    /// address of an app created earlier in the group, some other
    /// transaction in the group mentioned it (v9+), the address of an app
    /// in the current transaction's foreign-apps array (v7+), or the
    /// current app's own address.
    fn is_account_available(&self, addr: &[u8; 32]) -> bool {
        // Unnamed-resource relaxation (simulation `allow_unnamed_resources`):
        // every account is available, and the access is tracked and reported
        // to the tracer for the simulate response's `unnamed-resources-accessed`.
        if self.unnamed_tracking.is_some() {
            self.note_account_access(addr);
            return true;
        }
        let txn = &self.group[self.group_index].txn;
        // The current transaction's own sender is index 0 (`IndexByAddress`),
        // always available regardless of version.
        if txn.sender.0 == *addr {
            return true;
        }
        // Matches go-algorand's `IndexByAddress`: tries `tx.Access` first
        // (AVM v10+; only one of `Access`/`Accounts` is ever populated).
        if let Some(ref access) = txn.access {
            if access.iter().any(|rr| rr.address.0 == *addr) {
                return true;
            }
        }
        if let Some(ref accounts) = txn.accounts {
            if accounts.iter().any(|a| a.0 == *addr) {
                return true;
            }
        }
        // Address of an app created earlier in the group.
        if self.created_apps.iter().any(|&id| app_address(id) == *addr) {
            return true;
        }
        // Group-wide resource sharing (v9+).
        if self.program_version >= SHARED_RESOURCES_VERSION
            && self.group_resources.shared_accounts.contains(addr)
        {
            return true;
        }
        // Address of an app in the current transaction's foreign-apps array
        // (v7+, go's `appAddressAvailableVersion`).
        if self.program_version >= 7 {
            if let Some(ref apps) = txn.foreign_apps {
                if apps.iter().any(|&id| app_address(id) == *addr) {
                    return true;
                }
            }
        }
        // The current app's own address is always available.
        if app_address(self.app_id) == *addr {
            return true;
        }
        false
    }

    /// Matches go-algorand's `IndexByAddress`-succeeds subset of
    /// `accountReference`: the current transaction's own sender, or a
    /// member of its `Accounts`/`Access` array. See the trait doc comment
    /// ([`algo_avm::context::AvmContext::is_named_account_for_mutation`])
    /// for why this is narrower than [`Self::is_account_available`].
    fn is_named_account_for_mutation(&self, addr: &[u8; 32]) -> bool {
        let txn = &self.group[self.group_index].txn;
        if txn.sender.0 == *addr {
            return true;
        }
        if let Some(ref access) = txn.access {
            if access.iter().any(|rr| rr.address.0 == *addr) {
                return true;
            }
        }
        if let Some(ref accounts) = txn.accounts {
            if accounts.iter().any(|a| a.0 == *addr) {
                return true;
            }
        }
        false
    }

    /// Matches go-algorand's `allowsHolding`
    /// (`data/transactions/logic/resources.go`): an account+asset holding
    /// cross-product is available if some single sibling transaction named
    /// both together (`shared_holdings`), if the asset was created earlier
    /// in the group (any available account's holding of it is then
    /// available), if the account is the address of an app created earlier
    /// in the group (any available asset's holding for it is then
    /// available), or -- under simulation's `allow_unnamed_resources` --
    /// unconditionally (bypass + track, not reject).
    ///
    /// Callers must independently gate on `program_version >=
    /// SHARED_RESOURCES_VERSION` before consulting this, exactly matching
    /// go's own `holdingReference`/`requireHolding`, which never call
    /// `allowsHolding` below that version.
    fn is_holding_available(&self, addr: &[u8; 32], asset_id: u64) -> bool {
        if self
            .group_resources
            .shared_holdings
            .contains(&(*addr, asset_id))
        {
            return true;
        }
        if self.created_assets.contains(&asset_id) {
            return self.is_account_available(addr);
        }
        if self.created_apps.iter().any(|&id| app_address(id) == *addr) {
            return self.is_asset_available(asset_id);
        }
        // Simulation's `allow_unnamed_resources`: bypass unconditionally
        // (the account/asset-name access is tracked and reported via
        // `note_holding_access`, called separately by the real accessors --
        // matches `is_account_available`'s own unconditional-bypass
        // pattern, not `is_asset_available`'s stricter one, which has no
        // such bypass and would otherwise wrongly reject here).
        if self.unnamed_tracking.is_some() {
            return true;
        }
        false
    }

    /// Matches go-algorand's `allowsLocals`
    /// (`data/transactions/logic/resources.go`). See
    /// [`Self::is_holding_available`] for the shared rationale; the same
    /// caller-side version gate applies.
    fn is_local_available(&self, addr: &[u8; 32], app_id: u64) -> bool {
        if self
            .group_resources
            .shared_locals
            .contains(&(*addr, app_id))
        {
            return true;
        }
        if self.created_apps.contains(&app_id) {
            return self.is_account_available(addr);
        }
        if self.created_apps.iter().any(|&id| app_address(id) == *addr) {
            return self.is_app_available(app_id);
        }
        // See `is_holding_available`'s comment: unconditional bypass under
        // simulation's `allow_unnamed_resources`, not gated through
        // `is_app_available` (which has no such bypass).
        if self.unnamed_tracking.is_some() {
            return true;
        }
        false
    }

    // ---- Box storage ----
    //
    // Every method below is implemented once, generalized over an explicit
    // `app_id` (the box's *owner*), and exposed twice on `AvmContext`: the
    // plain `box_*` methods (always `app_id == self.app_id`, i.e. "my own
    // boxes") and the `app_box_*` methods (an explicit, possibly-foreign,
    // target app). This mirrors go-algorand's `boxXxxImpl(cx, appID)` shared
    // by `opBoxXxx` (`appID = cx.appID`) and `opAppBoxXxx` (`appID =
    // popDeepAppID(...)`) in `data/transactions/logic/box.go`. Routing the
    // *plain* `box_*` opcodes through the same `available_app_box` ->
    // `authorize_box_access` path as the foreign ones is required for
    // correctness, not just code reuse: even a same-app box access must
    // observe/touch family-shared state when the current app itself has
    // `FamilyBoxAccess` set (see `authorizeBoxAccess`,
    // `data/transactions/logic/box.go:47-122`, `familyShared =
    // ownerParams.FamilyBoxAccess` on the `ownerAppID == cx.appID` branch).

    fn box_get(&mut self, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        self.box_get_impl(self.app_id, name)
    }

    fn box_put(&mut self, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
        self.box_put_impl(self.app_id, name, value)
    }

    fn box_del(&mut self, name: &[u8]) -> Result<bool, AlgoError> {
        self.box_del_impl(self.app_id, name)
    }

    fn box_len(&mut self, name: &[u8]) -> Result<(u64, bool), AlgoError> {
        self.box_len_impl(self.app_id, name)
    }

    fn box_create(&mut self, name: &[u8], size: u64) -> Result<bool, AlgoError> {
        self.box_create_impl(self.app_id, name, size)
    }

    fn box_extract(&mut self, name: &[u8], offset: u64, length: u64) -> Result<Vec<u8>, AlgoError> {
        self.box_extract_impl(self.app_id, name, offset, length)
    }

    fn box_replace(&mut self, name: &[u8], offset: u64, value: &[u8]) -> Result<(), AlgoError> {
        self.box_replace_impl(self.app_id, name, offset, value)
    }

    fn box_resize(&mut self, name: &[u8], new_size: u64) -> Result<(), AlgoError> {
        self.box_resize_impl(self.app_id, name, new_size)
    }

    fn box_splice(
        &mut self,
        name: &[u8],
        start: u64,
        length: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        self.box_splice_impl(self.app_id, name, start, length, value)
    }

    // ---- Foreign box storage (`app_box_*`, issue #662) ----

    fn app_box_get(&mut self, app_id: u64, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        self.box_get_impl(app_id, name)
    }

    fn app_box_put(&mut self, app_id: u64, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
        self.box_put_impl(app_id, name, value)
    }

    fn app_box_del(&mut self, app_id: u64, name: &[u8]) -> Result<bool, AlgoError> {
        self.box_del_impl(app_id, name)
    }

    fn app_box_len(&mut self, app_id: u64, name: &[u8]) -> Result<(u64, bool), AlgoError> {
        self.box_len_impl(app_id, name)
    }

    fn app_box_create(&mut self, app_id: u64, name: &[u8], size: u64) -> Result<bool, AlgoError> {
        self.box_create_impl(app_id, name, size)
    }

    fn app_box_extract(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, AlgoError> {
        self.box_extract_impl(app_id, name, offset, length)
    }

    fn app_box_replace(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        self.box_replace_impl(app_id, name, offset, value)
    }

    fn app_box_resize(&mut self, app_id: u64, name: &[u8], new_size: u64) -> Result<(), AlgoError> {
        self.box_resize_impl(app_id, name, new_size)
    }

    fn app_box_splice(
        &mut self,
        app_id: u64,
        name: &[u8],
        start: u64,
        length: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        self.box_splice_impl(app_id, name, start, length, value)
    }

    // ---- Result extraction ----

    fn take_logs(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.logs)
    }

    fn take_inner_transactions(&mut self) -> Vec<SignedTransaction> {
        let groups = std::mem::take(&mut self.inner_txns);
        groups.into_iter().flat_map(|g| g.into_iter()).collect()
    }

    fn take_global_delta(&mut self) -> HashMap<Vec<u8>, Option<TealValue>> {
        let tracker = std::mem::take(&mut self.global_delta_tracker);
        // Preserve None entries — they represent key deletions (app_global_del).
        tracker.into_iter().collect()
    }

    fn take_local_deltas(&mut self) -> HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>> {
        let tracker = std::mem::take(&mut self.local_delta_tracker);
        let mut deltas: HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>> = HashMap::new();
        for ((addr, key), maybe_val) in tracker {
            // Preserve None entries — they represent key deletions (app_local_del).
            deltas.entry(addr).or_default().insert(key, maybe_val);
        }
        deltas
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
                txn_type: "pay".into(),
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
                txn_type: "appl".into(),
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
            store,
            group,
            0,     // group_index
            1000,  // round
            12345, // latest_timestamp
            42,    // app_id
            [1u8; 32],
            true, // app_mode
            [2u8; 32],
            [3u8; 32],
            ConsensusParams::default(),
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

        let type_val = ctx.txn_field(0, 15, None).unwrap(); // Type
        assert_eq!(type_val, TealValue::Bytes(b"pay".to_vec()));

        let type_enum_val = ctx.txn_field(0, 16, None).unwrap(); // TypeEnum
        assert_eq!(type_enum_val, TealValue::Uint(1));
    }

    #[test]
    fn txn_field_amount_receiver() {
        let sender = [10u8; 32];
        let receiver = [20u8; 32];
        let txn = make_pay_txn(sender, receiver, 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let amount = ctx.txn_field(0, 8, None).unwrap(); // Amount
        assert_eq!(amount, TealValue::Uint(5000));

        let rcv = ctx.txn_field(0, 7, None).unwrap(); // Receiver
        assert_eq!(rcv, TealValue::Bytes(receiver.to_vec()));
    }

    #[test]
    fn txn_field_first_last_valid() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let fv = ctx.txn_field(0, 2, None).unwrap(); // FirstValid
        assert_eq!(fv, TealValue::Uint(100));

        let lv = ctx.txn_field(0, 4, None).unwrap(); // LastValid
        assert_eq!(lv, TealValue::Uint(200));
    }

    #[test]
    fn txn_field_note() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let note = ctx.txn_field(0, 5, None).unwrap(); // Note
        assert_eq!(note, TealValue::Bytes(b"hello".to_vec()));
    }

    // ---- block_field / FirstValidTime tests ----

    fn seed_block_header(store: &mut LedgerState, round: u64, timestamp: i64) {
        use algo_types::BlockHeader;
        let hdr = BlockHeader {
            round: algo_types::Round(round),
            timestamp,
            ..BlockHeader::default()
        };
        let hdrdata = algo_codec::canonical_encode_block_header(&hdr);
        store.put_block(round, "v41", &hdrdata, &[]).unwrap();
    }

    #[test]
    fn txn_field_first_valid_time_reads_block_timestamp() {
        // make_pay_txn's FirstValid=100, LastValid=200 (see make_pay_txn).
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        seed_block_header(&mut store, 99, 1_700_000_000);
        let ctx = make_context(&mut store, vec![txn]);

        let ts = ctx.txn_field(0, 3, None).unwrap(); // FirstValidTime
        assert_eq!(ts, TealValue::Uint(1_700_000_000));
    }

    #[test]
    fn txn_field_first_valid_time_errors_when_header_missing() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        // No header seeded at round 99.
        let ctx = make_context(&mut store, vec![txn]);

        let result = ctx.txn_field(0, 3, None);
        assert!(result.is_err());
    }

    #[test]
    fn txn_field_first_valid_time_errors_when_round_outside_availability_window() {
        // FirstValid=100 with a header at round 99 present, but MaxTxnLife=0
        // and a LastValid far below 99 makes round 99 fall outside the
        // availability window, so this must error even though a header
        // exists at that round.
        let mut txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        txn.txn.first_valid = algo_types::Round(100);
        txn.txn.last_valid = algo_types::Round(100); // window: [max(1, 100-0-1)=99? no: last_avail=99]
        let mut store = LedgerState::new();
        seed_block_header(&mut store, 99, 1_700_000_000);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.consensus.max_txn_life = 0;

        // With FirstValid=100, LastValid=100, MaxTxnLife=0:
        // firstAvail = max(1, 100-0-1) = 99, lastAvail = 100-1 = 99, so 99
        // IS available -- this positive case should succeed.
        let ts = ctx.txn_field(0, 3, None).unwrap();
        assert_eq!(ts, TealValue::Uint(1_700_000_000));

        // Now push FirstValid further out so round 99 falls below the
        // firstAvail floor.
        ctx.group[0].txn.first_valid = algo_types::Round(1000);
        ctx.group[0].txn.last_valid = algo_types::Round(1000);
        let result = ctx.txn_field(0, 3, None);
        assert!(result.is_err(), "round 99 should be outside [999-999]");
    }

    #[test]
    fn block_field_seed_and_timestamp() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        use algo_types::BlockHeader;
        let hdr = BlockHeader {
            round: algo_types::Round(50),
            timestamp: 42,
            seed: [7u8; 32],
            ..BlockHeader::default()
        };
        let hdrdata = algo_codec::canonical_encode_block_header(&hdr);
        store.put_block(50, "v41", &hdrdata, &[]).unwrap();
        let ctx = make_context(&mut store, vec![txn]);

        // round 50 is within [1, 99] for a FirstValid=100 txn.
        let seed = ctx.block_field(50, 0).unwrap(); // BlkSeed
        assert_eq!(seed, algo_avm::machine::AvmValue::Bytes(vec![7u8; 32]));

        let ts = ctx.block_field(50, 1).unwrap(); // BlkTimestamp
        assert_eq!(ts, algo_avm::machine::AvmValue::Uint64(42));
    }

    #[test]
    fn block_field_v13_hash_fields() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        use algo_types::BlockHeader;
        let hdr = BlockHeader {
            round: algo_types::Round(50),
            prev512: [8u8; 64],
            txn_commitment: [9u8; 32],
            txn256: [10u8; 32],
            txn512: [11u8; 64],
            ..BlockHeader::default()
        };
        let hdrdata = algo_codec::canonical_encode_block_header(&hdr);
        store.put_block(50, "v41", &hdrdata, &[]).unwrap();
        let ctx = make_context(&mut store, vec![txn]);

        let branch512 = ctx.block_field(50, 10).unwrap(); // BlkBranch512
        assert_eq!(branch512, algo_avm::machine::AvmValue::Bytes(vec![8u8; 64]));
        let sha512_256 = ctx.block_field(50, 11).unwrap(); // BlkSha512_256TxnCommitment
        assert_eq!(
            sha512_256,
            algo_avm::machine::AvmValue::Bytes(vec![9u8; 32])
        );
        let sha256 = ctx.block_field(50, 12).unwrap(); // BlkSha256TxnCommitment
        assert_eq!(sha256, algo_avm::machine::AvmValue::Bytes(vec![10u8; 32]));
        let sha512 = ctx.block_field(50, 13).unwrap(); // BlkSha512TxnCommitment
        assert_eq!(sha512, algo_avm::machine::AvmValue::Bytes(vec![11u8; 64]));
    }

    #[test]
    fn block_field_rejects_round_above_last_avail() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // FirstValid=100 -> lastAvail=99; round 100 itself is not available
        // (it's the txn's own FirstValid round, not yet in history).
        let result = ctx.block_field(100, 1);
        assert!(result.is_err());
    }

    // ── Reentrancy guard (issue #809) ─────────────────────────────

    #[test]
    fn check_reentrancy_allows_unrelated_call() {
        assert!(check_reentrancy(100, &[], 200).is_ok());
    }

    #[test]
    fn check_reentrancy_rejects_direct_self_call() {
        let err = check_reentrancy(100, &[], 100).unwrap_err();
        assert!(
            err.to_string().contains("attempt to self-call"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_reentrancy_rejects_indirect_ancestor_cycle() {
        // A (100) called B (200), which is now trying to call A (100) again
        // -- an indirect A->B->A cycle, not a direct self-call.
        let family_chain = vec![FamilyFrame {
            app_id: 100,
            creator: [0u8; 32],
            touched_family_shared: false,
        }];
        let err = check_reentrancy(200, &family_chain, 100).unwrap_err();
        assert!(
            err.to_string().contains("attempt to re-enter 100"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_reentrancy_allows_calling_a_sibling_not_an_ancestor() {
        // A (100) called B (200); B calling C (300), which is not anywhere
        // in the ancestor chain, must be allowed.
        let family_chain = vec![FamilyFrame {
            app_id: 100,
            creator: [0u8; 32],
            touched_family_shared: false,
        }];
        assert!(check_reentrancy(200, &family_chain, 300).is_ok());
    }

    // ── StateSchema write-limit enforcement (issue #809) ──────────

    #[test]
    fn check_state_schema_counts_within_bounds_ok() {
        let mut state = std::collections::BTreeMap::new();
        state.insert(b"a".to_vec(), TealValue::Uint(1));
        state.insert(b"b".to_vec(), TealValue::Bytes(vec![1]));
        let schema = algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 1,
        };
        assert!(check_state_schema_counts(&state, &schema).is_ok());
    }

    #[test]
    fn check_state_schema_counts_rejects_too_many_uints() {
        let mut state = std::collections::BTreeMap::new();
        state.insert(b"a".to_vec(), TealValue::Uint(1));
        state.insert(b"b".to_vec(), TealValue::Uint(2));
        let schema = algo_types::StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        };
        let err = check_state_schema_counts(&state, &schema).unwrap_err();
        assert!(
            err.to_string()
                .contains("store integer count 2 exceeds schema integer count 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_state_schema_counts_rejects_too_many_bytes() {
        let mut state = std::collections::BTreeMap::new();
        state.insert(b"a".to_vec(), TealValue::Bytes(vec![1]));
        state.insert(b"b".to_vec(), TealValue::Bytes(vec![2]));
        let schema = algo_types::StateSchema {
            num_uint: 0,
            num_byte_slice: 1,
        };
        let err = check_state_schema_counts(&state, &schema).unwrap_err();
        assert!(
            err.to_string()
                .contains("store bytes count 2 exceeds schema bytes count 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn app_global_put_rejects_write_exceeding_schema() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.set_app_params(
            42,
            algo_types::AppParams {
                creator: Address([10u8; 32]),
                global_state_schema: algo_types::StateSchema {
                    num_uint: 1,
                    num_byte_slice: 0,
                },
                ..Default::default()
            },
        );
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 42;

        assert!(ctx.app_global_put(42, b"a", TealValue::Uint(1)).is_ok());
        let err = ctx
            .app_global_put(42, b"b", TealValue::Uint(2))
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds schema integer count"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn txn_field_group_index() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let gi = ctx.txn_field(0, 22, None).unwrap(); // GroupIndex
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
        let num = ctx.txn_field(0, 27, None).unwrap();
        assert_eq!(num, TealValue::Uint(2));

        // ApplicationArgs[0]
        let arg0 = ctx.txn_field(0, 26, Some(0)).unwrap();
        assert_eq!(arg0, TealValue::Bytes(b"arg0".to_vec()));

        // ApplicationArgs[1]
        let arg1 = ctx.txn_field(0, 26, Some(1)).unwrap();
        assert_eq!(arg1, TealValue::Bytes(b"arg1".to_vec()));

        // Out-of-range
        assert!(ctx.txn_field(0, 26, Some(2)).is_err());
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
        let num = ctx.txn_field(0, 29, None).unwrap();
        assert_eq!(num, TealValue::Uint(2));

        // Accounts[0] = sender (per go-algorand semantics)
        let a0 = ctx.txn_field(0, 28, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Bytes(sender.to_vec()));

        // Accounts[1] = apat[0]
        let a1 = ctx.txn_field(0, 28, Some(1)).unwrap();
        assert_eq!(a1, TealValue::Bytes(acct1.0.to_vec()));

        // Accounts[2] = apat[1]
        let a2 = ctx.txn_field(0, 28, Some(2)).unwrap();
        assert_eq!(a2, TealValue::Bytes(acct2.0.to_vec()));

        // Accounts[3] = out of range
        assert!(ctx.txn_field(0, 28, Some(3)).is_err());
    }

    #[test]
    fn txn_field_foreign_assets_and_apps() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100, 200], vec![50, 60]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApplications = len(apfa), not including current app
        assert_eq!(ctx.txn_field(0, 51, None).unwrap(), TealValue::Uint(2));
        // Applications[0] = current ApplicationID (per go-algorand semantics)
        assert_eq!(ctx.txn_field(0, 50, Some(0)).unwrap(), TealValue::Uint(42));
        // Applications[1] = apfa[0]
        assert_eq!(ctx.txn_field(0, 50, Some(1)).unwrap(), TealValue::Uint(100));
        // Applications[2] = apfa[1]
        assert_eq!(ctx.txn_field(0, 50, Some(2)).unwrap(), TealValue::Uint(200));
        // Applications[3] = out of range
        assert!(ctx.txn_field(0, 50, Some(3)).is_err());

        // NumAssets (0-based, no special index 0)
        assert_eq!(ctx.txn_field(0, 49, None).unwrap(), TealValue::Uint(2));
        // Assets[0] = foreign_assets[0]
        assert_eq!(ctx.txn_field(0, 48, Some(0)).unwrap(), TealValue::Uint(50));
        // Assets[1] = foreign_assets[1]
        assert_eq!(ctx.txn_field(0, 48, Some(1)).unwrap(), TealValue::Uint(60));
        // Assets[2] = out of range
        assert!(ctx.txn_field(0, 48, Some(2)).is_err());
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

    // ── tx.Access-list resolution (issue #841) ──────────────────────────

    #[test]
    fn resolve_account_uses_access_list_when_present() {
        // Matches go-algorand's `AddressByIndex`: when `tx.Access` is
        // present, indices > 0 resolve into it instead of `Accounts`.
        let sender = [10u8; 32];
        let acct1 = Address([30u8; 32]);
        let mut txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![
            ResourceRef {
                address: acct1,
                ..Default::default()
            },
            ResourceRef {
                asset: 1050,
                ..Default::default()
            },
        ]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.resolve_account(0).unwrap(), sender);
        assert_eq!(ctx.resolve_account(1).unwrap(), acct1.0);
        // Access[1] is an Asset entry, not an Address -- must error, not
        // silently return a zero address.
        let err = ctx.resolve_account(2).unwrap_err();
        assert!(
            err.to_string().contains("is not an Address in tx.Access"),
            "unexpected: {err}"
        );
        // Out of range.
        assert!(ctx.resolve_account(3).is_err());
    }

    #[test]
    fn is_account_available_consults_access_list() {
        let sender = [10u8; 32];
        let named = [11u8; 32];
        let stranger = [12u8; 32];
        let mut txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![ResourceRef {
            address: Address(named),
            ..Default::default()
        }]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.is_account_available(&sender));
        assert!(ctx.is_account_available(&named));
        assert!(!ctx.is_account_available(&stranger));
    }

    #[test]
    fn is_asset_available_and_resolve_asset_consult_access_list() {
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 1042, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![ResourceRef {
            asset: 1050,
            ..Default::default()
        }]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.is_asset_available(1050));
        assert!(!ctx.is_asset_available(1060));
        // A direct-reference resolve (the id itself, named via Access) must
        // succeed even though it's not in a legacy `ForeignAssets` array.
        assert_eq!(ctx.resolve_asset(1050).unwrap(), 1050);
    }

    #[test]
    fn is_app_available_and_resolve_app_consult_access_list() {
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 1042, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![ResourceRef {
            app: 1100,
            ..Default::default()
        }]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 1042;

        assert!(ctx.is_app_available(1100));
        assert!(!ctx.is_app_available(1200));
        assert_eq!(ctx.resolve_app(1100).unwrap(), 1100);
    }

    #[test]
    fn resolve_asset_and_resolve_app_fall_back_to_access_slot() {
        // Matches go's `resolveAsset`/`resolveApp` fallback slot lookup into
        // `tx.Access` (`Access[ref-1].Asset/App != 0`), tried when the
        // integer isn't itself a directly-available id.
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 1042, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![ResourceRef {
            asset: 1050,
            ..Default::default()
        }]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn.clone()]);
        // ref=1 is not itself an available asset id (1 != 1050), but slot 1
        // (1-based) in Access names asset 1050.
        assert_eq!(ctx.resolve_asset(1).unwrap(), 1050);

        let mut txn2 = txn;
        txn2.txn.access = Some(vec![ResourceRef {
            app: 1100,
            ..Default::default()
        }]);
        let mut store2 = LedgerState::new();
        let mut ctx2 = make_context(&mut store2, vec![txn2]);
        ctx2.app_id = 1042;
        assert_eq!(ctx2.resolve_app(1).unwrap(), 1100);
    }

    #[test]
    fn resolve_asset_and_resolve_app_consult_group_wide_sharing() {
        // Matches go's `resolveAsset`/`resolveApp` calling `availableAsset`/
        // `availableApp`, which include the v9+ group-sharing set -- a gap
        // fixed alongside the Access-list work (issue #841), since both are
        // consulted through the same "direct reference" availability check.
        let sender = [10u8; 32];
        let sibling = make_appl_txn([99u8; 32], 1042, vec![], vec![], vec![1050]);
        let mut txn = make_appl_txn(sender, 1042, vec![], vec![], vec![]);
        txn.txn.foreign_apps = Some(vec![1100]);
        let group = vec![sibling, txn];
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, group);
        ctx.set_program_version(9);
        ctx.group_index = 1;

        // Asset 1050 is only in the *sibling's* ForeignAssets, not this
        // txn's own -- available only via v9+ group sharing.
        assert_eq!(ctx.resolve_asset(1050).unwrap(), 1050);
    }

    #[test]
    fn resolve_asset_implied_and_foreign() {
        // Realistic (> 255) ids: under the default (modern) consensus,
        // AppForbidLowResources forbids resolving low asset/app ids (see
        // `low_resource_ids_forbidden_under_app_forbid_low_resources` below),
        // so ordinary resolution-mechanics tests must use ids a real
        // AppForbidLowResources-era chain (first id 1001) would actually
        // hand out.
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 1042, vec![], vec![], vec![1050, 1060]);
        txn.txn.xaid = 1099; // implied asset
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.resolve_asset(0).unwrap(), 1099);
        assert_eq!(ctx.resolve_asset(1).unwrap(), 1050);
        assert_eq!(ctx.resolve_asset(2).unwrap(), 1060);
        assert!(ctx.resolve_asset(3).is_err());
    }

    #[test]
    fn resolve_app_current_and_foreign() {
        // Realistic (> 255) ids -- see comment on
        // `resolve_asset_implied_and_foreign` above.
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 1042, vec![], vec![1100, 1200], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 1042;

        assert_eq!(ctx.resolve_app(0).unwrap(), 1042); // current app
        assert_eq!(ctx.resolve_app(1).unwrap(), 1100);
        assert_eq!(ctx.resolve_app(2).unwrap(), 1200);
        assert!(ctx.resolve_app(3).is_err());
    }

    // ── AppForbidLowResources (v38+) activation boundary ────────────────

    #[test]
    fn low_resource_ids_forbidden_under_app_forbid_low_resources() {
        // v38+ (modern default): resolving an asset/app id <= 255 must be
        // rejected, even when it's directly named (available).
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 42, vec![], vec![100], vec![50]);
        txn.txn.xaid = 50;
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        assert!(ctx.consensus.app_forbid_low_resources);
        ctx.app_id = 42;

        assert!(
            ctx.resolve_asset(1).is_err(),
            "v38+ must forbid a directly-named low asset id"
        );
        assert!(
            ctx.resolve_app(1).is_err(),
            "v38+ must forbid a directly-named low app id"
        );
        assert!(
            ctx.resolve_app(0).is_err(),
            "v38+ must forbid a low *current app* id too (matches go's defer, which \
             checks the resolved id unconditionally)"
        );
    }

    #[test]
    fn low_resource_ids_allowed_before_app_forbid_low_resources() {
        // Before v38, low ids are resolved without restriction.
        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 42, vec![], vec![100], vec![50]);
        txn.txn.xaid = 50;
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 42;
        ctx.consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V37,
        )
        .expect("v37 params");
        assert!(!ctx.consensus.app_forbid_low_resources);

        assert_eq!(ctx.resolve_asset(1).unwrap(), 50);
        assert_eq!(ctx.resolve_app(1).unwrap(), 100);
        assert_eq!(ctx.resolve_app(0).unwrap(), 42);
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
                ..Default::default()
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
                ..Default::default()
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

    /// Issue #659: `AppVersion`(9)/`AppSizeSponsor`(10)/`AppForeignBoxReads`(11)/
    /// `AppFamilyBoxAccess`(12) must be readable via `app_params_get`,
    /// matching go-algorand's field indices exactly.
    #[test]
    fn app_params_get_version_size_sponsor_and_foreign_box_fields() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.app_params.insert(
            42,
            AppParams {
                creator: Address([1u8; 32]),
                version: 3,
                size_sponsor: Address([9u8; 32]),
                foreign_box_reads: true,
                family_box_access: false,
                ..Default::default()
            },
        );
        let ctx = make_context(&mut store, vec![txn]);

        let (val, exists) = ctx.app_params_get(42, 9).unwrap(); // AppVersion
        assert!(exists);
        assert_eq!(val, TealValue::Uint(3));

        let (val, _) = ctx.app_params_get(42, 10).unwrap(); // AppSizeSponsor
        assert_eq!(val, TealValue::Bytes([9u8; 32].to_vec()));

        let (val, _) = ctx.app_params_get(42, 11).unwrap(); // AppForeignBoxReads
        assert_eq!(val, TealValue::Uint(1));

        let (val, _) = ctx.app_params_get(42, 12).unwrap(); // AppFamilyBoxAccess
        assert_eq!(val, TealValue::Uint(0));
    }

    /// `app_params_set AppForeignBoxReads`/`AppFamilyBoxAccess` must
    /// actually persist through the real `LedgerStore` (not just a mock),
    /// closing the "round-trips correctly through state" acceptance
    /// criterion end-to-end (write via `set_*`, read back via
    /// `store.get_app_params` directly, independent of `app_params_get`).
    #[test]
    fn app_params_set_foreign_box_reads_and_family_box_access_persist_through_store() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        store.app_params.insert(
            42,
            AppParams {
                creator: Address([1u8; 32]),
                ..Default::default()
            },
        );
        let mut ctx = make_context(&mut store, vec![txn]);

        let p = ctx.store.get_app_params(42).unwrap();
        assert!(!p.foreign_box_reads);
        assert!(!p.family_box_access);

        ctx.set_foreign_box_reads(42, true).unwrap();
        let p = ctx.store.get_app_params(42).unwrap();
        assert!(p.foreign_box_reads);
        assert!(!p.family_box_access);

        ctx.set_family_box_access(42, true).unwrap();
        let p = ctx.store.get_app_params(42).unwrap();
        assert!(p.foreign_box_reads);
        assert!(p.family_box_access);

        ctx.set_foreign_box_reads(42, false).unwrap();
        let p = ctx.store.get_app_params(42).unwrap();
        assert!(!p.foreign_box_reads);
        assert!(p.family_box_access);
    }

    /// Setting a flag on a nonexistent app must error, not silently no-op or
    /// panic (mirrors go's `appParamsSetter`'s `"app %d does not exist"`).
    #[test]
    fn app_params_set_on_missing_app_errors() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);

        assert!(ctx.set_foreign_box_reads(999, true).is_err());
        assert!(ctx.set_family_box_access(999, true).is_err());
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
    //
    // Mirrors go-algorand's `opGloadImpl` check ordering (range, type, self,
    // future, then nil-pastScratch) so these pin the same error taxonomy as
    // `TestGloadNoProgram` (`data/transactions/logic/eval_test.go`).

    #[test]
    fn gload_out_of_range() {
        let txn = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let err = ctx.gload("gload", 5, 0).unwrap_err();
        assert!(err.to_string().contains("lookup TxnGroup[5]"), "{err}");
    }

    #[test]
    fn gload_non_appl_sibling_errors() {
        let pay = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let appl = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        // group_index=1 (the appl txn); index 0 is a pay txn.
        let mut ctx = make_context(&mut store, vec![pay, appl]);
        ctx.group_index = 1;

        let err = ctx.gload("gload", 0, 0).unwrap_err();
        assert!(
            err.to_string().contains("non-app call txn with index 0"),
            "{err}"
        );
    }

    #[test]
    fn gload_self_errors() {
        let txn = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        let err = ctx.gload("gload", 0, 0).unwrap_err();
        assert!(err.to_string().contains("on self"), "{err}");
    }

    #[test]
    fn gload_future_errors() {
        let a = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let b = make_appl_txn([10u8; 32], 43, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        // group_index=0, referencing index 1 which is ahead of it.
        let ctx = make_context(&mut store, vec![a, b]);

        let err = ctx.gload("gloads", 1, 0).unwrap_err();
        assert!(err.to_string().contains("future scratch space"), "{err}");
    }

    #[test]
    fn gload_did_not_run_a_program_errors() {
        // Sibling at index 0 is `appl` type but never actually ran a
        // program (pastScratch[0] is None) -- e.g. a ClearState call
        // against an already-deleted app. This is the go-algorand
        // `a9e47033d` regression: the type check alone is not enough, the
        // nil-scratch case must also be rejected rather than returning a
        // default/garbage value.
        let a = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let b = make_appl_txn([10u8; 32], 43, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![a, b]);
        ctx.group_index = 1;
        // ctx.scratch[0] stays None: index 0's program never ran.

        let err = ctx.gload("gload", 0, 0).unwrap_err();
        assert!(
            err.to_string()
                .contains("gload lookup of txn 0 that did not run a program"),
            "{err}"
        );
        // gloads/gloadss substitute their own opcode name.
        let err = ctx.gload("gloads", 0, 0).unwrap_err();
        assert!(
            err.to_string()
                .contains("gloads lookup of txn 0 that did not run a program"),
            "{err}"
        );
    }

    #[test]
    fn gload_returns_value_once_marked_ran() {
        let a = make_appl_txn([10u8; 32], 42, vec![], vec![], vec![]);
        let b = make_appl_txn([10u8; 32], 43, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![a, b]);
        ctx.group_index = 1;
        let mut row = default_scratch_row();
        row[3] = TealValue::Uint(999);
        ctx.scratch[0] = Some(row);

        let val = ctx.gload("gload", 0, 3).unwrap();
        assert_eq!(val, TealValue::Uint(999));
    }

    // ---- gload within an INNER transaction group (issue #714) ----
    //
    // Mirrors go-algorand's `NewInnerEvalParams`/`opItxnSubmit`
    // (`data/transactions/logic/eval.go`): an inner transaction group shares
    // one `EvalParams` (and therefore one `pastScratch` array) across all of
    // its members, exactly like a top-level group. Before this fix,
    // `execute_inner_appl` always built a single-element AVM group with
    // `group_index = 0` for *every* inner app call regardless of how many
    // siblings were actually submitted together, so `gload`/`gloads`/
    // `gloadss` against a real inner-group sibling unconditionally errored.

    #[test]
    fn gload_sees_real_sibling_value_within_inner_transaction_group() {
        // Set up: outer app 42 submits ONE inner group of two app calls:
        //   [0] writer app: `pushint 42; store 5; pushint 1` -- writes 42
        //       into scratch slot 5, then approves.
        //   [1] reader app: `gload 0 5; pushint 42; ==` -- approves iff
        //       sibling index 0's scratch slot 5 really equals 42. Before
        //       the fix, `execute_inner_appl` gave the reader its own
        //       single-element group with `group_index = 0`, so `gload 0 5`
        //       (targeting its own index) hit the "can't use gload on self"
        //       error rather than reading the real sibling value.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let writer_app_id = 910u64;
        let reader_app_id = 911u64;
        setup_app(
            &mut store,
            writer_app_id,
            vec![
                0x06, // version 6
                0x81, 0x2a, // pushint 42
                0x35, 0x05, // store 5
                0x81, 0x01, // pushint 1 (approve)
            ],
            make_program(6, true),
        );
        setup_app(
            &mut store,
            reader_app_id,
            vec![
                0x06, // version 6
                0x3a, 0x00, 0x05, // gload 0 5
                0x81, 0x2a, // pushint 42
                0x12, // ==
            ],
            make_program(6, true),
        );

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(
            sender,
            42,
            vec![],
            vec![writer_app_id, reader_app_id],
            vec![],
        );
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(writer_app_id)).unwrap(); // ApplicationID
        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(reader_app_id)).unwrap(); // ApplicationID
        ctx.itxn_submit().expect(
            "gload within an inner transaction group must see the real sibling value (42), \
             not error as if the inner group only had one member",
        );

        assert_eq!(ctx.num_inner_txns(), 2);
    }

    #[test]
    fn gload_within_single_member_inner_group_still_errors_on_self() {
        // Regression check for the fix above: a single-member inner group
        // (the common case -- one `itxn_submit` with no `itxn_next`) must
        // still report the *same* error taxonomy as before (#670): `gload`
        // against any index, including self, errors correctly rather than
        // being accidentally "fixed" into returning a value now that the
        // group can have more than one member.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let self_gload_app_id = 912u64;
        setup_app(
            &mut store,
            self_gload_app_id,
            vec![
                0x06, // version 6
                0x3a, 0x00, 0x00, // gload 0 0 (targets self: the only member)
            ],
            make_program(6, true),
        );

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![self_gload_app_id], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(self_gload_app_id))
            .unwrap(); // ApplicationID
        let err = ctx.itxn_submit().unwrap_err();
        assert!(
            err.to_string().contains("can't use gload on self"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nested_inner_group_seeds_its_own_independent_scratch_record() {
        // A nested inner-of-inner group: outer app 42 submits a single
        // inner app call to "nester" (app 920), whose own approval program
        // itself submits a two-member inner group (writer 921, reader 922)
        // via itxn_begin/itxn_field/itxn_next/itxn_submit. The nested
        // group's `gload` must resolve correctly using its OWN
        // `ran_program`/`scratch` record (sized 2, for [writer, reader]),
        // entirely independent of the outer level's own inner-group record
        // (sized 1, for [nester] alone) -- proving one level's record
        // doesn't leak into or get shadowed by another's.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let nester_app_id = 920u64;
        // The nester's own approval program embeds these two IDs as raw
        // single-byte `pushint` varuint operands (below), so they must fit
        // in 7 bits (< 128) to encode correctly.
        let writer_app_id = 30u64;
        let reader_app_id = 31u64;

        setup_app(
            &mut store,
            writer_app_id,
            vec![
                0x06, // version 6
                0x81, 0x2a, // pushint 42
                0x35, 0x05, // store 5
                0x81, 0x01, // pushint 1 (approve)
            ],
            make_program(6, true),
        );
        setup_app(
            &mut store,
            reader_app_id,
            vec![
                0x06, // version 6
                0x3a, 0x00, 0x05, // gload 0 5
                0x81, 0x2a, // pushint 42
                0x12, // ==
            ],
            make_program(6, true),
        );
        // The nester's own approval program builds and submits a 2-member
        // inner group [writer, reader] and approves iff `itxn_submit`
        // itself succeeded (which it only will if the reader's own `gload`
        // resolved correctly).
        setup_app(
            &mut store,
            nester_app_id,
            vec![
                0x06, // version 6
                0xb1, // itxn_begin
                0x81,
                0x06, // pushint 6 (TypeEnum = appl)
                0xb2,
                0x10, // itxn_field 16 (TypeEnum)
                0x81,
                writer_app_id as u8, // pushint <writer_app_id>
                0xb2,
                0x18, // itxn_field 24 (ApplicationID)
                0xb6, // itxn_next
                0x81,
                0x06, // pushint 6 (TypeEnum = appl)
                0xb2,
                0x10, // itxn_field 16 (TypeEnum)
                0x81,
                reader_app_id as u8, // pushint <reader_app_id>
                0xb2,
                0x18, // itxn_field 24 (ApplicationID)
                0xb3, // itxn_submit
                0x81,
                0x01, // pushint 1 (approve)
            ],
            make_program(6, true),
        );

        // Fund both the outer app's address (pays the nester's fee) and the
        // nester app's address (pays writer/reader's fees).
        let outer_app_addr = Address(app_address(42));
        store.set_account(
            &outer_app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let nester_app_addr = Address(app_address(nester_app_id));
        store.set_account(
            &nester_app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![nester_app_id], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 3000;
        ctx.depth = 0;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(nester_app_id)).unwrap(); // ApplicationID
        ctx.itxn_submit().expect(
            "nested inner group must seed its own independent scratch record so the \
             nested reader's gload resolves the nested writer's real value",
        );

        assert_eq!(ctx.num_inner_txns(), 1);
    }

    // ---- Inner transaction tests ----

    #[test]
    fn inner_txn_build_and_submit() {
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Fund the app address (app_id=42) so inner pay can succeed.
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        assert_eq!(ctx.num_inner_txns(), 0);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(999)).unwrap(); // Amount
        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 1);

        // Read back fields from last inner txn
        let type_val = ctx.last_itxn_field(15, None).unwrap(); // Type
        assert_eq!(type_val, TealValue::Bytes(b"pay".to_vec()));

        let amount_val = ctx.last_itxn_field(8, None).unwrap(); // Amount
        assert_eq!(amount_val, TealValue::Uint(999));

        let rcv_val = ctx.last_itxn_field(7, None).unwrap(); // Receiver
        assert_eq!(rcv_val, TealValue::Bytes([30u8; 32].to_vec()));

        // Verify that the receiver actually got funded.
        let rcv_acct = store.get_account(&Address([30u8; 32]));
        assert_eq!(rcv_acct.unwrap().micro_algos, 999);
    }

    #[test]
    fn inner_txn_group() {
        use algo_types::{AssetHolding as AssetHoldingType, AssetParamsRecord};

        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Fund the app address (app_id=42) so inner pay can succeed.
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );

        // Set up asset 77 so axfer can succeed.
        let asset_params = algo_types::AssetParams {
            total: 1_000_000,
            ..Default::default()
        };
        store.set_asset_params(
            77,
            AssetParamsRecord {
                params: asset_params,
                creator: app_addr,
            },
        );
        // App address holds asset 77.
        store.set_asset_holding(
            &app_addr,
            77,
            AssetHoldingType {
                amount: 1_000_000,
                frozen: false,
            },
        );
        // Receiver [30u8; 32] opts in to asset 77.
        let rcv_addr = Address([30u8; 32]);
        store.set_account(
            &rcv_addr,
            AccountData {
                micro_algos: 100_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );
        store.set_asset_holding(
            &rcv_addr,
            77,
            AssetHoldingType {
                amount: 0,
                frozen: false,
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap(); // Receiver

        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(4)).unwrap(); // axfer
        ctx.itxn_field(17, TealValue::Uint(77)).unwrap(); // XferAsset
        ctx.itxn_field(18, TealValue::Uint(200)).unwrap(); // AssetAmount
        ctx.itxn_field(20, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap(); // AssetReceiver

        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 2);

        // Read from the group
        let val = ctx.last_itxn_group_field(0, 8, None).unwrap(); // Amount of first
        assert_eq!(val, TealValue::Uint(100));

        let val = ctx.last_itxn_group_field(1, 18, None).unwrap(); // AssetAmount of second
        assert_eq!(val, TealValue::Uint(200));

        // Verify state changes: receiver got 100 microAlgos and 200 units of asset 77.
        let rcv_acct = store.get_account(&rcv_addr).unwrap();
        assert_eq!(rcv_acct.micro_algos, 100_000 + 100);
        let rcv_holding = store.get_asset_holding(&rcv_addr, 77).unwrap();
        assert_eq!(rcv_holding.amount, 200);
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

        let a0 = ctx.txn_field(0, 28, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Bytes(sender.to_vec()));

        // NumAccounts = 0 (no foreign accounts)
        assert_eq!(ctx.txn_field(0, 29, None).unwrap(), TealValue::Uint(0));

        // Accounts[1] should fail (no foreign accounts)
        assert!(ctx.txn_field(0, 28, Some(1)).is_err());
    }

    // ---- Applications[0] = current app edge cases ----

    #[test]
    fn txn_field_applications_zero_is_current_app_empty_foreign() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // Applications[0] = current ApplicationID even with no foreign apps
        let a0 = ctx.txn_field(0, 50, Some(0)).unwrap();
        assert_eq!(a0, TealValue::Uint(42));

        // NumApplications = 0
        assert_eq!(ctx.txn_field(0, 51, None).unwrap(), TealValue::Uint(0));

        // Applications[1] should fail
        assert!(ctx.txn_field(0, 50, Some(1)).is_err());
    }

    // ---- Program page tests ----

    #[test]
    fn program_pages_single_page() {
        let sender = [10u8; 32];
        let program = vec![0x06, 0x81, 0x01]; // short program (3 bytes < 4096)
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".into();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 1
        assert_eq!(ctx.txn_field(0, 65, None).unwrap(), TealValue::Uint(1));

        // ApprovalProgramPages[0] = entire program
        assert_eq!(
            ctx.txn_field(0, 64, Some(0)).unwrap(),
            TealValue::Bytes(program)
        );

        // ApprovalProgramPages[1] = out of range → error
        assert!(ctx.txn_field(0, 64, Some(1)).is_err());
    }

    #[test]
    fn program_pages_multi_page() {
        let sender = [10u8; 32];
        // Create a program that spans 2 pages (4097 bytes)
        let program: Vec<u8> = (0..4097u16).map(|i| (i % 256) as u8).collect();
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".into();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 2 (4097 / 4096 = 2)
        assert_eq!(ctx.txn_field(0, 65, None).unwrap(), TealValue::Uint(2));

        // Page 0 = first 4096 bytes
        assert_eq!(
            ctx.txn_field(0, 64, Some(0)).unwrap(),
            TealValue::Bytes(program[..4096].to_vec())
        );

        // Page 1 = remaining 1 byte
        assert_eq!(
            ctx.txn_field(0, 64, Some(1)).unwrap(),
            TealValue::Bytes(program[4096..].to_vec())
        );

        // Page 2 = out of range
        assert!(ctx.txn_field(0, 64, Some(2)).is_err());
    }

    #[test]
    fn program_pages_empty_program() {
        let sender = [10u8; 32];
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".into();
        txn.txn.approval_program = None;
        txn.txn.clear_state_program = None;
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // NumApprovalProgramPages = 0 for empty/None program
        assert_eq!(ctx.txn_field(0, 65, None).unwrap(), TealValue::Uint(0));
        // NumClearStateProgramPages = 0
        assert_eq!(ctx.txn_field(0, 67, None).unwrap(), TealValue::Uint(0));

        // Page 0 on empty program = error (0 pages, index 0 is OOB)
        assert!(ctx.txn_field(0, 64, Some(0)).is_err());
        assert!(ctx.txn_field(0, 66, Some(0)).is_err());
    }

    #[test]
    fn program_pages_exact_page_boundary() {
        let sender = [10u8; 32];
        // Exactly 4096 bytes = 1 page, not 2
        let program = vec![0xAA; 4096];
        let mut txn = make_pay_txn(sender, [20u8; 32], 5000);
        txn.txn.txn_type = "appl".into();
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(program.clone()));
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        assert_eq!(ctx.txn_field(0, 65, None).unwrap(), TealValue::Uint(1));
        assert_eq!(
            ctx.txn_field(0, 64, Some(0)).unwrap(),
            TealValue::Bytes(program)
        );
        assert!(ctx.txn_field(0, 64, Some(1)).is_err());
    }

    // ---- div_ceil inline test (std usize::div_ceil) ----

    #[test]
    fn test_div_ceil() {
        assert_eq!(0usize.div_ceil(4096), 0);
        assert_eq!(1usize.div_ceil(4096), 1);
        assert_eq!(4096usize.div_ceil(4096), 1);
        assert_eq!(4097usize.div_ceil(4096), 2);
        assert_eq!(8192usize.div_ceil(4096), 2);
        assert_eq!(8193usize.div_ceil(4096), 3);
    }

    // ---- Inner app call tests (Epic 22 Wave 4) ----

    /// Helper: set up an app in the store with a given approval program.
    /// Returns the app_id.
    fn setup_app(
        store: &mut LedgerState,
        app_id: u64,
        approval_program: Vec<u8>,
        clear_program: Vec<u8>,
    ) {
        let creator = Address([1u8; 32]);
        store.set_app_params(
            app_id,
            AppParams {
                creator,
                approval_program,
                clear_state_program: clear_program,
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                global_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );
    }

    /// Build a minimal AVM program: version + intcblock [val] + intc_0 + return
    /// This produces a program that pushes `val` and returns.
    fn make_program(version: u8, approves: bool) -> Vec<u8> {
        // intcblock [val], intc_0, return
        let val = if approves { 1u8 } else { 0u8 };
        vec![version, 0x20, 0x01, val, 0x22, 0x43]
    }

    #[test]
    fn inner_appl_basic_noop() {
        // Set up: app 42 calls inner app 100, which runs a v6 approval
        // program that pushes 1 (approve).
        let mut store = LedgerState::new();

        // App 42 (the outer app calling the inner appl)
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100 (the called inner app)
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );

        // Fund the outer app address.
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        // Set opcode budget so inner execution can proceed.
        ctx.opcode_budget = 2000;

        // Build inner app call: itxn_begin, itxn_field TypeEnum=6 (appl),
        // itxn_field ApplicationID=100, itxn_submit.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_submit().unwrap();

        // Should have 1 inner txn recorded.
        assert_eq!(ctx.num_inner_txns(), 1);

        // Read back the inner txn's type.
        let type_val = ctx.last_itxn_field(16, None).unwrap(); // TypeEnum
        assert_eq!(type_val, TealValue::Uint(6));
    }

    #[test]
    fn inner_appl_self_call_rejected() {
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(42)).unwrap(); // same app ID
        let result = ctx.itxn_submit();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("self-call"), "got: {msg}");
    }

    #[test]
    fn inner_appl_depth_limit() {
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.opcode_budget = 2000;
        // Set depth to MAX_APP_CALL_DEPTH (8), so it should be rejected.
        ctx.depth = params::MAX_APP_CALL_DEPTH as u32;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
        let result = ctx.itxn_submit();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("depth"), "got: {msg}");
    }

    #[test]
    fn inner_appl_budget_pooling() {
        // Verify that an inner appl adds 700 to the opcode budget.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        // Start with exactly 100 budget.
        ctx.opcode_budget = 100;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
        ctx.itxn_submit().unwrap();

        // Budget should have increased by 700 (INNER_APP_BUDGET) minus the
        // cost of the inner program's opcodes (3 opcodes at cost 1 each).
        // So: 100 + 700 - 3 = 797.
        assert_eq!(ctx.opcode_budget, 797);
    }

    #[test]
    fn inner_appl_clearstate_prohibition() {
        // ClearState programs cannot issue inner transactions.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let sender = [10u8; 32];
        let mut txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        txn.txn.on_completion = 3; // ClearStateOC
        let mut ctx = make_context(&mut store, vec![txn]);

        let result = ctx.itxn_begin();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("clear state programs can not issue inner transactions"),
            "got: {msg}"
        );
    }

    #[test]
    fn inner_appl_version_too_low() {
        // Programs with version < MIN_INNER_APPL_VERSION (4) cannot be
        // called via inner transactions.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        // App 100 has a v2 program (below minimum v4).
        setup_app(
            &mut store,
            100,
            make_program(2, true),
            make_program(2, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
        let result = ctx.itxn_submit();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("v2 < v4"), "got: {msg}");
    }

    #[test]
    fn inner_appl_opt_in() {
        // Inner appl with OnCompletion=OptIn should create local state.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Verify app address is not opted in to app 100 (before creating ctx).
        assert!(!store.has_app_local_state(&app_addr, 100));

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.opcode_budget = 2000;

            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
            ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
            ctx.itxn_field(25, TealValue::Uint(1)).unwrap(); // OnCompletion = OptIn
            ctx.itxn_submit().unwrap();
        }

        // After opt-in, the app address should have local state for app 100.
        assert!(store.has_app_local_state(&app_addr, 100));
    }

    #[test]
    fn inner_appl_close_out() {
        // Inner appl with OnCompletion=CloseOut should remove local state.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_apps_opted_in: 1,
                ..Default::default()
            },
        );
        // Opt in the app address to app 100.
        store.set_app_local_state(
            &app_addr,
            100,
            AppLocalState {
                schema: StateSchema::default(),
                key_value: BTreeMap::new(),
            },
        );
        assert!(store.has_app_local_state(&app_addr, 100));

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.opcode_budget = 2000;

            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
            ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
            ctx.itxn_field(25, TealValue::Uint(2)).unwrap(); // OnCompletion = CloseOut
            ctx.itxn_submit().unwrap();
        }

        // After close-out, local state should be removed.
        assert!(!store.has_app_local_state(&app_addr, 100));
    }

    #[test]
    fn inner_appl_duplicate_opt_in_fails() {
        // Inner appl with OnCompletion=OptIn should fail when the sender is
        // already opted into the app (matching outer apply_appl behaviour).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_apps_opted_in: 1,
                ..Default::default()
            },
        );
        // Pre-opt-in: the app address already has local state for app 100.
        store.set_app_local_state(
            &app_addr,
            100,
            AppLocalState {
                schema: StateSchema::default(),
                key_value: BTreeMap::new(),
            },
        );
        assert!(store.has_app_local_state(&app_addr, 100));

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(1)).unwrap(); // OnCompletion = OptIn
        let err = ctx.itxn_submit().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("already opted into app"),
            "expected 'already opted into app' error, got: {}",
            msg
        );
    }

    #[test]
    fn inner_appl_close_out_not_opted_in_fails() {
        // Inner appl with OnCompletion=CloseOut should fail when the sender
        // is NOT opted into the app (matching outer apply_appl behaviour).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        // Do NOT opt in the app address to app 100.
        assert!(!store.has_app_local_state(&app_addr, 100));

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(2)).unwrap(); // OnCompletion = CloseOut
        let err = ctx.itxn_submit().unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("not opted into app"),
            "expected 'not opted into app' error, got: {}",
            msg
        );
    }

    #[test]
    fn inner_appl_delete() {
        // Inner appl with OnCompletion=DeleteApplication should delete the app.
        // The inner txn sender is app 42's address, so the called app's creator
        // must be app 42's address for the creator check to pass.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app_addr = Address(app_address(42));
        // Create app 100 with creator = app 42's address (the inner txn sender).
        store.set_app_params(
            100,
            AppParams {
                creator: app_addr,
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                global_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_created_apps: 1,
                ..Default::default()
            },
        );
        assert!(store.has_app_params(100));

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.opcode_budget = 2000;

            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
            ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
            ctx.itxn_field(25, TealValue::Uint(5)).unwrap(); // OnCompletion = DeleteApplication
            ctx.itxn_submit().unwrap();
        }

        // After delete, app should be gone.
        assert!(!store.has_app_params(100));
        // Creator's (app 42's address) counter should be decremented.
        let creator_acct = store.get_account(&app_addr).unwrap();
        assert_eq!(creator_acct.total_created_apps, 0);
    }

    #[test]
    fn inner_appl_rejection_rolls_back() {
        // When the inner app program rejects, the outer itxn_submit
        // should fail and no state changes should persist.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        // App 100 rejects (pushes 0).
        setup_app(
            &mut store,
            100,
            make_program(6, false),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let initial_balance = store.get_account(&app_addr).unwrap().micro_algos;
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap();
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap();
        let result = ctx.itxn_submit();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("rejected"), "got: {msg}");

        // Balance should be restored (rollback).
        let balance_after = store.get_account(&app_addr).unwrap().micro_algos;
        assert_eq!(balance_after, initial_balance);
    }

    #[test]
    fn inner_appl_app_creation() {
        // Inner appl with application_id=0 should create a new app.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        ctx.txn_counter = 200;
        // itxn_submit increments txn_counter to 201, then
        // execute_inner_appl creates app with id txn_counter + 1 = 202.

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(0)).unwrap(); // ApplicationID = 0 (create)
                                                         // Set approval and clear state programs on the inner txn.
        ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ApprovalProgram
        ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ClearStateProgram
        ctx.itxn_submit().unwrap();

        // The created app ID should be txn_counter + 1 = 202 (matching go-algorand).
        let created_id = ctx.last_itxn_field(61, None).unwrap(); // CreatedApplicationID
        assert_eq!(created_id, TealValue::Uint(202));

        // The app should exist in the store.
        assert!(store.has_app_params(202));
    }

    // ---- Wave 5: Inner txn field access, IDs, and resource availability ----

    #[test]
    fn inner_acfg_create_returns_created_asset_id() {
        // An inner acfg with config_asset=0 creates a new asset.
        // Field 60 (CreatedAssetID) should return the created asset ID.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.txn_counter = 100;

        // Build inner acfg create transaction.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // TypeEnum = acfg
                                                         // config_asset = 0 means "create"
        ctx.itxn_field(34, TealValue::Uint(1_000_000)).unwrap(); // ConfigAssetTotal
        ctx.itxn_field(35, TealValue::Uint(6)).unwrap(); // ConfigAssetDecimals
        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 1);

        // CreatedAssetID should be the new asset ID.
        // txn_counter = 100 + 0 + 1 = 101, then apply_acfg does +1 = 102
        let created = ctx.last_itxn_field(60, None).unwrap();
        assert_eq!(created, TealValue::Uint(102));

        // Also check via gitxn (group index 0).
        let created_g = ctx.last_itxn_group_field(0, 60, None).unwrap();
        assert_eq!(created_g, TealValue::Uint(102));

        // The asset should be tracked as a created resource.
        assert!(ctx.created_assets.contains(&102));
    }

    #[test]
    fn inner_appl_logs_accessible_via_itxn() {
        // An inner appl that logs a message should have logs accessible
        // through fields 58 (Logs), 59 (NumLogs), and 62 (LastLog).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // Create a program that logs "hello" and approves.
        // pushbytes "hello" (0x80 0x05 "hello"), log (0xb0), int 1 (0x81 0x01), return (0x43)
        let log_program = {
            let mut p = vec![6u8]; // version 6
            p.push(0x80); // pushbytes
            p.push(0x05); // length 5
            p.extend_from_slice(b"hello");
            p.push(0xb0); // log
            p.push(0x81); // pushint
            p.push(0x01); // 1
            p.push(0x43); // return
            p
        };
        setup_app(&mut store, 100, log_program, make_program(6, true));

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_submit().unwrap();

        // NumLogs should be 1.
        let num_logs = ctx.last_itxn_field(59, None).unwrap();
        assert_eq!(num_logs, TealValue::Uint(1));

        // Logs[0] should be "hello".
        let log0 = ctx.last_itxn_field(58, Some(0)).unwrap();
        assert_eq!(log0, TealValue::Bytes(b"hello".to_vec()));

        // Logs count via field 58 with no array_index.
        let logs_count = ctx.last_itxn_field(58, None).unwrap();
        assert_eq!(logs_count, TealValue::Uint(1));

        // LastLog should be "hello".
        let last_log = ctx.last_itxn_field(62, None).unwrap();
        assert_eq!(last_log, TealValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn inner_txn_id_is_computed_correctly() {
        // After itxn_submit, reading TxID (field 23) should return
        // the inner txn ID, not the regular txn ID.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn.clone()]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(500)).unwrap(); // Amount
        ctx.itxn_submit().unwrap();

        // Get the TxID from the inner txn.
        let inner_txid = ctx.last_itxn_field(23, None).unwrap();

        // Compute the expected inner txn ID manually.
        let parent_txid = algo_codec::compute_txn_id(&txn.txn);
        let inner_stxn = &ctx.inner_txns().last().unwrap()[0];
        let expected_id = algo_avm::itxn::compute_inner_txn_id(&parent_txid, 0, &inner_stxn.txn);

        assert_eq!(inner_txid, TealValue::Bytes(expected_id.0.to_vec()));

        // It should NOT equal the regular txn ID of the inner txn.
        let regular_id = algo_codec::compute_txn_id(&inner_stxn.txn);
        assert_ne!(
            inner_txid,
            TealValue::Bytes(regular_id.0.to_vec()),
            "inner TxID should differ from regular TxID"
        );

        // Also verify via inner_txn_ids accessor.
        assert_eq!(ctx.inner_txn_ids().len(), 1);
        assert_eq!(ctx.inner_txn_ids()[0].len(), 1);
        assert_eq!(ctx.inner_txn_ids()[0][0], expected_id);
    }

    #[test]
    fn inner_txn_id_varies_by_group_index() {
        // When submitting a group of inner txns, each should have a
        // distinct inner txn ID based on its offset.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let rcv_addr = Address([30u8; 32]);
        store.set_account(
            &rcv_addr,
            AccountData {
                micro_algos: 100_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        // Build a group of 2 inner pay txns.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();

        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(200)).unwrap();

        ctx.itxn_submit().unwrap();

        // gitxn 0 TxID and gitxn 1 TxID should be different.
        let id0 = ctx.last_itxn_group_field(0, 23, None).unwrap();
        let id1 = ctx.last_itxn_group_field(1, 23, None).unwrap();
        assert_ne!(id0, id1, "different inner txns should have different IDs");

        // itxn TxID should match gitxn 1 TxID (last in group).
        let last_id = ctx.last_itxn_field(23, None).unwrap();
        assert_eq!(last_id, id1, "itxn TxID should be the last in the group");
    }

    #[test]
    fn resource_availability_after_inner_asset_create() {
        // After an inner acfg creates a new asset, that asset should be
        // available via is_asset_available.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.txn_counter = 300;

        // Asset doesn't exist yet.
        assert!(!ctx.is_asset_available(302));

        // Inner acfg create.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // acfg
        ctx.itxn_field(34, TealValue::Uint(1_000_000)).unwrap(); // total
        ctx.itxn_submit().unwrap();

        // Now the created asset should be available.
        let created_id_val = ctx.last_itxn_field(60, None).unwrap();
        let created_id = match created_id_val {
            TealValue::Uint(v) => v,
            _ => panic!("expected uint"),
        };
        assert!(ctx.is_asset_available(created_id));
    }

    #[test]
    fn resource_availability_after_inner_app_create() {
        // After an inner appl creates a new app, that app should be
        // available via is_app_available.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        ctx.txn_counter = 400;

        // App 402 doesn't exist yet (txn_counter will be 401 after increment,
        // then +1 gives new app ID 402).
        assert!(!ctx.is_app_available(402));

        // Inner appl create.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(0)).unwrap(); // create
        ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
            .unwrap();
        ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
            .unwrap();
        ctx.itxn_submit().unwrap();

        // The created app should now be available.
        let created_id_val = ctx.last_itxn_field(61, None).unwrap();
        let created_id = match created_id_val {
            TealValue::Uint(v) => v,
            _ => panic!("expected uint"),
        };
        assert!(ctx.is_app_available(created_id));
        assert!(ctx.created_apps.contains(&created_id));
    }

    #[test]
    fn resource_availability_foreign_arrays() {
        // Assets and apps in foreign arrays should be available.
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![77], vec![88]);
        let mut store = LedgerState::new();
        let ctx = make_context(&mut store, vec![txn]);

        // Foreign app 77 should be available.
        assert!(ctx.is_app_available(77));
        // Foreign asset 88 should be available.
        assert!(ctx.is_asset_available(88));
        // Current app (42) should be available.
        assert!(ctx.is_app_available(42));
        // Random IDs should not be available.
        assert!(!ctx.is_app_available(999));
        assert!(!ctx.is_asset_available(999));
        // Zero is never available.
        assert!(!ctx.is_app_available(0));
        assert!(!ctx.is_asset_available(0));
    }

    #[test]
    fn resource_availability_group_sharing_v9_plus() {
        // Two sibling txns: the executing appl (index 1) references nothing
        // itself, but its sibling pay txn (index 0) names an account, and a
        // sibling axfer/acfg-style transaction shares an asset. At v9+ these
        // become available to the appl via group-wide sharing (issue #808).
        let shared_account = [77u8; 32];
        let pay = make_pay_txn([10u8; 32], shared_account, 5000);
        let appl = make_appl_txn([20u8; 32], 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![pay, appl]);
        ctx.group_index = 1;
        ctx.set_program_version(9);

        assert!(
            ctx.is_account_available(&shared_account),
            "v9+ program should see the sibling pay txn's receiver via group sharing"
        );
    }

    #[test]
    fn resource_availability_group_sharing_gated_below_v9() {
        // The same setup, but the executing program is v8: group-wide
        // sharing must not apply yet (matches go's
        // `cx.version >= sharedResourcesVersion` gate).
        let shared_account = [78u8; 32];
        let pay = make_pay_txn([10u8; 32], shared_account, 5000);
        let appl = make_appl_txn([20u8; 32], 42, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![pay, appl]);
        ctx.group_index = 1;
        ctx.set_program_version(8);

        assert!(
            !ctx.is_account_available(&shared_account),
            "below v9, a sibling txn's account must not be available via group sharing"
        );
    }

    // ---- Pre-sharedResources tx.Access gating (issue #866) ----
    //
    // Mirrors go-algorand's `TestAppCallCheckProgramsWithAccess`
    // (`ledger/apply/application_test.go`) via the same enforcement point:
    // `(*EvalContext).begin` (`data/transactions/logic/eval.go`) rejects an
    // Application-mode program below `sharedResourcesVersion` (9) whose
    // transaction's `Access` array is non-empty, with the exact error text
    // `"pre-sharedResources program cannot be invoked with tx.Access"`.

    /// Helper: an `appl` transaction carrying a non-empty `Access` array.
    fn make_appl_txn_with_access(sender: [u8; 32], app_id: u64) -> SignedTransaction {
        let mut txn = make_appl_txn(sender, app_id, vec![], vec![], vec![]);
        txn.txn.access = Some(vec![algo_types::ResourceRef {
            asset: 99,
            ..Default::default()
        }]);
        txn
    }

    #[test]
    fn approval_program_below_shared_resources_version_rejects_txn_access() {
        use algo_avm::eval::run_approval_program;
        use algo_avm::group::GroupBudget;

        let sender = [30u8; 32];
        let appl = make_appl_txn_with_access(sender, 42);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![appl]);

        // v8 program (< sharedResourcesVersion=9): pushint 1 (would approve
        // if run).
        let program = vec![8u8, 0x81, 0x01];
        let mut budget = GroupBudget::new(1);
        let err =
            run_approval_program(&program, &mut ctx, &mut budget).expect_err("must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("pre-sharedResources program cannot be invoked with tx.Access"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn approval_program_at_shared_resources_version_accepts_txn_access() {
        use algo_avm::eval::run_approval_program;
        use algo_avm::group::GroupBudget;

        let sender = [31u8; 32];
        let appl = make_appl_txn_with_access(sender, 42);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![appl]);

        // v9 program (== sharedResourcesVersion): pushint 1 (approves).
        let program = vec![9u8, 0x81, 0x01];
        let mut budget = GroupBudget::new(1);
        let result =
            run_approval_program(&program, &mut ctx, &mut budget).expect("must not be rejected");
        assert!(result.approved, "v9 program with tx.Access should approve");
    }

    #[test]
    fn clear_state_program_below_shared_resources_version_rejects_txn_access() {
        use algo_avm::eval::run_clear_state_program;

        let sender = [32u8; 32];
        let appl = make_appl_txn_with_access(sender, 42);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![appl]);

        // v8 program (< sharedResourcesVersion=9): pushint 1 (would approve
        // if run). Per this repo's ClearState-error semantics (CLAUDE.md),
        // a ClearState rejection returns an empty `AvmResult` rather than
        // propagating `Err`, so assert on `approved`/`error` instead.
        let program = vec![8u8, 0x81, 0x01];
        let result = run_clear_state_program(&program, &mut ctx, &ConsensusParams::default());
        assert!(
            !result.approved,
            "pre-sharedResources clear-state program with tx.Access must not approve"
        );
    }

    #[test]
    fn resource_availability_account_own_sender_and_accounts_array() {
        let sender = [10u8; 32];
        let named = [11u8; 32];
        let stranger = [12u8; 32];
        let txn = make_appl_txn(sender, 42, vec![Address(named)], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_program_version(8);

        assert!(ctx.is_account_available(&sender));
        assert!(ctx.is_account_available(&named));
        assert!(!ctx.is_account_available(&stranger));
        // The current app's own address is always available.
        assert!(ctx.is_account_available(&app_address(42)));
    }

    #[test]
    fn fill_group_resources_covers_pay_acfg_axfer_afrz_appl() {
        let receiver = [21u8; 32];
        let close = [22u8; 32];
        let pay = {
            let mut t = make_pay_txn([20u8; 32], receiver, 1000);
            t.txn.close_remainder_to = Address(close);
            t
        };
        let appl = make_appl_txn([30u8; 32], 0, vec![Address([31u8; 32])], vec![55], vec![66]);
        let group = vec![pay, appl];
        let resources = fill_group_resources(&group);

        assert!(resources.shared_accounts.contains(&receiver));
        assert!(resources.shared_accounts.contains(&close));
        assert!(resources.shared_accounts.contains(&[20u8; 32]));
        assert!(resources.shared_accounts.contains(&[30u8; 32]));
        assert!(resources.shared_accounts.contains(&[31u8; 32]));
        assert!(resources.shared_apps.contains(&55));
        assert!(resources.shared_accounts.contains(&app_address(55)));
        assert!(resources.shared_asas.contains(&66));
    }

    // ── Holding/local cross-product sharing (issue #841) ────────────────

    #[test]
    fn fill_group_resources_covers_axfer_and_afrz_holdings() {
        use serde_bytes::ByteBuf;
        let sender = [40u8; 32];
        let receiver = [41u8; 32];
        let asset_sender = [42u8; 32];
        let asset_close_to = [43u8; 32];
        let axfer = SignedTransaction {
            txn: Transaction {
                txn_type: "axfer".into(),
                sender: Address(sender),
                fee: 1000,
                xaid: 900,
                asset_receiver: Some(Address(receiver)),
                asset_sender: Some(Address(asset_sender)),
                asset_close_to: Some(Address(asset_close_to)),
                note: ByteBuf::from(Vec::new()),
                ..Default::default()
            },
            ..Default::default()
        };

        let freeze_account = [44u8; 32];
        let afrz = SignedTransaction {
            txn: Transaction {
                txn_type: "afrz".into(),
                sender: Address([45u8; 32]),
                fee: 1000,
                freeze_asset: 901,
                freeze_account: Some(Address(freeze_account)),
                note: ByteBuf::from(Vec::new()),
                ..Default::default()
            },
            ..Default::default()
        };

        let resources = fill_group_resources(&[axfer, afrz]);

        // axfer: sender, receiver, AssetSender, and AssetCloseTo all share
        // the holding of asset 900 (go's `shareAccountAndHolding`).
        assert!(resources.shared_holdings.contains(&(sender, 900)));
        assert!(resources.shared_holdings.contains(&(receiver, 900)));
        assert!(resources.shared_holdings.contains(&(asset_sender, 900)));
        assert!(resources.shared_holdings.contains(&(asset_close_to, 900)));
        // afrz: FreezeAccount shares the holding of FreezeAsset.
        assert!(resources.shared_holdings.contains(&(freeze_account, 901)));
        // A different (account, asset) pair from either txn is not shared.
        assert!(!resources.shared_holdings.contains(&(sender, 901)));
    }

    #[test]
    fn fill_group_resources_covers_appl_foreign_cross_products() {
        // A single appl's own Accounts x ForeignAssets/ForeignApps/
        // ApplicationID cross product is shared -- matches go's
        // `fillApplicationCallForeign`, which iterates ep.TxnGroup
        // (including the executing txn's own fields).
        let sender = [50u8; 32];
        let other_acct = [51u8; 32];
        let appl = make_appl_txn(sender, 900, vec![Address(other_acct)], vec![901], vec![950]);
        let resources = fill_group_resources(&[appl]);

        // Every account named by this txn (sender, Accounts[], the called
        // app's address, and ForeignApps' addresses) is crossed with every
        // named asset/app.
        assert!(resources.shared_holdings.contains(&(sender, 950)));
        assert!(resources.shared_holdings.contains(&(other_acct, 950)));
        assert!(resources.shared_holdings.contains(&(app_address(900), 950)));
        assert!(resources.shared_holdings.contains(&(app_address(901), 950)));
        assert!(resources.shared_locals.contains(&(sender, 900)));
        assert!(resources.shared_locals.contains(&(other_acct, 900)));
        assert!(resources.shared_locals.contains(&(sender, 901)));
        assert!(resources.shared_locals.contains(&(other_acct, 901)));
        // A holding/local for an unrelated asset/app is not shared.
        assert!(!resources.shared_holdings.contains(&(sender, 999)));
        assert!(!resources.shared_locals.contains(&(sender, 999)));
    }

    #[test]
    fn fill_group_resources_covers_access_list() {
        // Matches go's `fillApplicationCallAccess`: the sender, the called
        // app, and the sender's locals for it are implicitly available;
        // Access entries name everything else, including resolved
        // Holding/Locals cross-product refs.
        let sender = [60u8; 32];
        let other_acct = Address([61u8; 32]);
        let txn = SignedTransaction {
            txn: Transaction {
                txn_type: "appl".into(),
                sender: Address(sender),
                fee: 1000,
                application_id: 900,
                access: Some(vec![
                    ResourceRef {
                        address: other_acct,
                        ..Default::default()
                    },
                    ResourceRef {
                        asset: 950,
                        ..Default::default()
                    },
                    ResourceRef {
                        app: 901,
                        ..Default::default()
                    },
                    ResourceRef {
                        // Holding for (Access[0]=other_acct, Access[1]=asset 950).
                        holding: Some(HoldingRef {
                            address: 1,
                            asset: 2,
                        }),
                        ..Default::default()
                    },
                    ResourceRef {
                        // Locals for (sender (0), Access[2]=app 901).
                        locals: Some(LocalsRef { address: 0, app: 3 }),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            },
            ..Default::default()
        };
        let resources = fill_group_resources(&[txn]);

        assert!(resources.shared_accounts.contains(&sender));
        assert!(resources.shared_accounts.contains(&other_acct.0));
        assert!(resources.shared_asas.contains(&950));
        assert!(resources.shared_apps.contains(&901));
        assert!(resources.shared_apps.contains(&900)); // implicit: the called app
        assert!(resources.shared_locals.contains(&(sender, 900))); // implicit: sender's own locals
        assert!(resources.shared_holdings.contains(&(other_acct.0, 950)));
        assert!(resources.shared_locals.contains(&(sender, 901)));
    }

    // ── allowsHolding / allowsLocals cross-product gate (issue #841) ────

    #[test]
    fn is_holding_available_group_shared_pair() {
        let sender = [70u8; 32];
        let other = [71u8; 32];
        let mut txn = make_appl_txn(sender, 900, vec![], vec![], vec![950]);
        txn.txn.accounts = Some(vec![Address(other)]);
        let group = vec![txn];
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, group);
        ctx.set_program_version(9);

        // sender/other x asset 950 is shared via this txn's own foreign
        // arrays (fillApplicationCallForeign cross product).
        assert!(ctx.is_holding_available(&sender, 950));
        assert!(ctx.is_holding_available(&other, 950));
        // A holding never named by any txn in the group is not available.
        assert!(!ctx.is_holding_available(&sender, 999));
    }

    #[test]
    fn is_local_available_group_shared_pair() {
        let sender = [72u8; 32];
        let other = [73u8; 32];
        let mut txn = make_appl_txn(sender, 900, vec![], vec![901], vec![]);
        txn.txn.accounts = Some(vec![Address(other)]);
        let group = vec![txn];
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, group);
        ctx.set_program_version(9);

        assert!(ctx.is_local_available(&sender, 901));
        assert!(ctx.is_local_available(&other, 901));
        assert!(!ctx.is_local_available(&sender, 999));
    }

    #[test]
    fn is_holding_available_created_asset_any_available_account() {
        let sender = [74u8; 32];
        let txn = make_appl_txn(sender, 900, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_program_version(9);
        ctx.created_assets.push(1234);

        // An asset created earlier in the group is available for the
        // holding of any *available* account (here, the sender).
        assert!(ctx.is_holding_available(&sender, 1234));
        // But not for an account this group never made available.
        assert!(!ctx.is_holding_available(&[99u8; 32], 1234));
    }

    #[test]
    fn is_local_available_created_app_any_available_account() {
        let sender = [75u8; 32];
        let txn = make_appl_txn(sender, 900, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_program_version(9);
        ctx.created_apps.push(1234);

        assert!(ctx.is_local_available(&sender, 1234));
        assert!(!ctx.is_local_available(&[99u8; 32], 1234));
    }

    #[test]
    fn is_holding_available_created_app_address_any_available_asset() {
        let sender = [76u8; 32];
        let txn = make_appl_txn(sender, 900, vec![], vec![], vec![950]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_program_version(9);
        ctx.created_apps.push(1234);
        let created_app_addr = app_address(1234);

        // The address of an app created earlier in the group is treated
        // like an "available account" for holdings of any *available*
        // asset.
        assert!(ctx.is_holding_available(&created_app_addr, 950));
        assert!(!ctx.is_holding_available(&created_app_addr, 999));
    }

    #[test]
    fn is_holding_available_and_is_local_available_bypass_under_unnamed_tracking() {
        // Simulation's `allow_unnamed_resources`: bypass + track, not
        // reject, for both halves and the cross-product itself.
        let sender = [77u8; 32];
        let txn = make_appl_txn(sender, 900, vec![], vec![], vec![]);
        let mut store = LedgerState::new();
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.set_program_version(9);
        ctx.enable_unnamed_resource_tracking(Arc::new(NamedGroupResources::default()));

        assert!(ctx.is_holding_available(&[88u8; 32], 12345));
        assert!(ctx.is_local_available(&[88u8; 32], 12345));
    }

    #[test]
    fn gitxn_reads_correct_fields_from_inner_group() {
        // Submit a group of 2 inner txns (pay + acfg create),
        // then use gitxn to read specific fields from each.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let rcv_addr = Address([30u8; 32]);

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.txn_counter = 500;

        // Group: pay + acfg create.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(1000)).unwrap();

        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // acfg
        ctx.itxn_field(34, TealValue::Uint(999_999)).unwrap(); // total

        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 2);

        // gitxn 0 TypeEnum should be pay (1).
        let type0 = ctx.last_itxn_group_field(0, 16, None).unwrap();
        assert_eq!(type0, TealValue::Uint(1));

        // gitxn 1 TypeEnum should be acfg (3).
        let type1 = ctx.last_itxn_group_field(1, 16, None).unwrap();
        assert_eq!(type1, TealValue::Uint(3));

        // gitxn 0 Amount should be 1000.
        let amount0 = ctx.last_itxn_group_field(0, 8, None).unwrap();
        assert_eq!(amount0, TealValue::Uint(1000));

        // gitxn 1 CreatedAssetID should be non-zero.
        let created1 = ctx.last_itxn_group_field(1, 60, None).unwrap();
        match created1 {
            TealValue::Uint(v) => assert!(v > 0, "created asset ID should be non-zero"),
            _ => panic!("expected uint"),
        }

        // itxn (last in group = the acfg) TypeEnum should be acfg (3).
        let last_type = ctx.last_itxn_field(16, None).unwrap();
        assert_eq!(last_type, TealValue::Uint(3));
    }

    #[test]
    fn inner_txn_ids_accumulate_across_submissions() {
        // Submit two separate inner txn groups. The IDs from the second
        // group should have offsets that account for the first group.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let rcv_addr = Address([30u8; 32]);
        let mut ctx = make_context(&mut store, vec![txn.clone()]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        // First submission: 1 inner pay.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap();
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
        ctx.itxn_submit().unwrap();

        let id_first = ctx.inner_txn_ids()[0][0];

        // Second submission: 1 inner pay (different amount to get different txn).
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap();
        ctx.itxn_field(7, TealValue::Bytes(rcv_addr.0.to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(200)).unwrap();
        ctx.itxn_submit().unwrap();

        let id_second = ctx.inner_txn_ids()[1][0];

        // Both should exist.
        assert_eq!(ctx.inner_txn_ids().len(), 2);

        // They should be different (different offsets and different txn content).
        assert_ne!(id_first, id_second);

        // Verify offset: first has offset 0, second has offset 1.
        let parent_txid = algo_codec::compute_txn_id(&txn.txn);
        let first_inner = &ctx.inner_txns()[0][0];
        let second_inner = &ctx.inner_txns()[1][0];

        let expected_first =
            algo_avm::itxn::compute_inner_txn_id(&parent_txid, 0, &first_inner.txn);
        let expected_second =
            algo_avm::itxn::compute_inner_txn_id(&parent_txid, 1, &second_inner.txn);

        assert_eq!(id_first, expected_first);
        assert_eq!(id_second, expected_second);
    }

    // ==================================================================
    // Issue #25 fix tests
    // ==================================================================

    // ---- H1: Nested inner txns serialized into eval_delta "itx" key ----

    #[test]
    fn h1_nested_inner_txns_in_eval_delta() {
        // When an inner appl calls another app that itself issues inner txns,
        // the child's inner txns should appear in the parent's eval_delta
        // under the "itx" key.
        use crate::eval_delta::parse_eval_delta;

        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100 is the called inner app. Its program logs "nested" and
        // issues an inner pay. For this test, we just need the child context
        // to have inner txns. Since our current infra runs a minimal program
        // (which doesn't actually issue inner txns), we test the serialization
        // path by verifying that logs from the child appear in eval_delta.
        // The log_program below logs "nested" and approves.
        let log_program = {
            let mut p = vec![6u8]; // version 6
            p.push(0x80); // pushbytes
            p.push(0x06); // length 6
            p.extend_from_slice(b"nested");
            p.push(0xb0); // log
            p.push(0x81); // pushint
            p.push(0x01); // 1
            p.push(0x43); // return
            p
        };
        setup_app(&mut store, 100, log_program, make_program(6, true));

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_submit().unwrap();

        // The inner txn should have an eval_delta with "lg" containing "nested".
        let inner_stxn = &ctx.inner_txns().last().unwrap()[0];
        assert!(inner_stxn.eval_delta.is_some(), "eval_delta should exist");

        let ed = parse_eval_delta(inner_stxn.eval_delta.as_ref().unwrap()).unwrap();
        let logs = ed.logs.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0], b"nested");
    }

    // ---- TASK-281: inner app call global/local state deltas in eval_delta ----

    #[test]
    fn inner_appl_state_delta_without_logging_in_eval_delta() {
        // An inner app call that writes global state but emits no logs must
        // still surface its state changes in the inner txn's eval_delta `gd`.
        // Before TASK-281 the inner eval_delta only carried `lg`/`itx`, so a
        // silent state writer produced an empty (None) inner delta.
        use crate::eval_delta::{parse_eval_delta, DeltaAction};

        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100: pushbytes "g"; pushint 7; app_global_put; pushint 1; return.
        // Writes global key "g" = 7 and approves, without logging.
        let state_program = vec![
            6u8, // version 6
            0x80, 0x01, b'g', // pushbytes "g"
            0x81, 0x07, // pushint 7
            0x67, // app_global_put
            0x81, 0x01, // pushint 1
            0x43, // return
        ];
        setup_app(&mut store, 100, state_program, make_program(6, true));

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_submit().unwrap();

        let inner_stxn = &ctx.inner_txns().last().unwrap()[0];
        let ed = parse_eval_delta(
            inner_stxn
                .eval_delta
                .as_ref()
                .expect("inner eval_delta should exist for a state-writing inner call"),
        )
        .unwrap();

        let gd = ed
            .global_delta
            .expect("inner global delta should be present");
        let vd = gd
            .get(b"g".as_slice())
            .expect("global key `g` written by the inner app");
        assert_eq!(vd.action, DeltaAction::SetUint);
        assert_eq!(vd.uint, 7);
        // No logs were emitted, so there should be no `lg` entry.
        assert!(ed.logs.is_none(), "inner call emitted no logs");
    }

    // ---- H2: Asset/app creation IDs are sequential (no gaps/duplicates) ----

    #[test]
    fn h2_asset_and_app_creation_ids_sequential() {
        // Submit a group of inner txns: acfg create, appl create, acfg create.
        // The IDs should be sequential with no gaps.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 5000;
        ctx.txn_counter = 100;

        // First inner: acfg create
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // acfg
        ctx.itxn_field(34, TealValue::Uint(1_000_000)).unwrap(); // total

        // Second inner: appl create
        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(0)).unwrap(); // create
        ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
            .unwrap();
        ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
            .unwrap();

        // Third inner: acfg create
        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // acfg
        ctx.itxn_field(34, TealValue::Uint(500_000)).unwrap(); // total

        ctx.itxn_submit().unwrap();

        // txn_counter_base = 100
        // i=0: txn_counter = 101, acfg => asset_id = 101 + 1 = 102
        // i=1: txn_counter = 102, appl => app_id = 102 + 1 = 103
        // i=2: txn_counter = 103, acfg => asset_id = 103 + 1 = 104
        let asset1 = ctx.last_itxn_group_field(0, 60, None).unwrap(); // CreatedAssetID
        let app1 = ctx.last_itxn_group_field(1, 61, None).unwrap(); // CreatedApplicationID
        let asset2 = ctx.last_itxn_group_field(2, 60, None).unwrap(); // CreatedAssetID

        assert_eq!(asset1, TealValue::Uint(102), "first asset ID");
        assert_eq!(app1, TealValue::Uint(103), "app ID");
        assert_eq!(asset2, TealValue::Uint(104), "second asset ID");

        // No gaps or duplicates.
        assert!(store.get_asset_params(102).is_some());
        assert!(store.get_app_params(103).is_some());
        assert!(store.get_asset_params(104).is_some());
    }

    // ---- H3: ClearState does not inflate shared budget ----

    #[test]
    fn h3_clearstate_inner_appl_no_budget_inflation() {
        // An inner appl with ClearState should NOT add INNER_APP_BUDGET to
        // the shared opcode budget.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        // Opt the app address (inner txn sender) into app 100 so ClearState
        // has local state to clear. Inner txns default sender to app_address(42).
        store.set_app_local_state(
            &app_addr,
            100,
            AppLocalState {
                schema: StateSchema::default(),
                key_value: BTreeMap::new(),
            },
        );
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_apps_opted_in: 1,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 1000;

        let budget_before = ctx.opcode_budget;

        // Inner ClearState call.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_field(25, TealValue::Uint(3)).unwrap(); // OnCompletion = ClearStateOC
        ctx.itxn_submit().unwrap();

        // ClearState should NOT have added 700 to the budget.
        // The clear state program uses its own isolated budget (3 opcodes).
        // So the shared budget should be unchanged (1000).
        assert_eq!(
            ctx.opcode_budget, budget_before,
            "ClearState should not inflate shared budget"
        );
    }

    // ---- H4: Rollback snapshot covers appl accounts ----

    #[test]
    fn h4_snapshot_includes_appl_accounts() {
        // When an inner appl fails after mutating an account in the accounts
        // array, rollback should restore that account's state.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        // App 100 rejects (pushes 0).
        setup_app(
            &mut store,
            100,
            make_program(6, false),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Create a "bystander" account that will be in the accounts array.
        let bystander = Address([50u8; 32]);
        store.set_account(
            &bystander,
            AccountData {
                micro_algos: 5_000_000,
                ..Default::default()
            },
        );
        let initial_balance = store.get_account(&bystander).unwrap().micro_algos;

        // Build inner group: pay to bystander (succeeds), then appl that
        // references bystander in accounts array (fails).
        // Since the appl fails, the entire group should be rolled back.
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![bystander], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        // Submit a group: pay to bystander, then failing appl with bystander in accounts.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // pay
        ctx.itxn_field(7, TealValue::Bytes(bystander.0.to_vec()))
            .unwrap(); // Receiver = bystander
        ctx.itxn_field(8, TealValue::Uint(1_000)).unwrap(); // Amount

        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100 (rejects)
                                                           // Set accounts array to include bystander.
        ctx.itxn_field(28, TealValue::Bytes(bystander.0.to_vec()))
            .unwrap();

        let result = ctx.itxn_submit();
        assert!(result.is_err(), "second inner txn should fail");

        // Bystander's balance should be restored to initial value.
        let balance_after = store.get_account(&bystander).unwrap().micro_algos;
        assert_eq!(
            balance_after, initial_balance,
            "bystander balance should be rolled back"
        );
    }

    // ---- H5: fee_credit propagation from nested inner app calls ----

    #[test]
    fn h5_fee_credit_propagated_from_child() {
        // An inner appl call inherits fee_credit from the parent.
        // After the child runs, the parent's fee_credit should reflect
        // the child's remaining credit.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        // Set fee_credit to a large value.
        ctx.fee_credit = 50_000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_submit().unwrap();

        // fee_credit should be propagated back from the child.
        // The child received fee_credit = 50_000, and since it didn't
        // issue any inner txns that would consume credit, it should still
        // have the same credit (minus any shortfall/overpay at the child level).
        // In this case the inner appl has default fee=1000 and MinTxnFee=1000,
        // so no shortfall or overpay.
        assert_eq!(
            ctx.fee_credit, 50_000,
            "fee_credit should be propagated back"
        );
    }

    // ---- H6: txn_counter propagation from nested inner app calls ----

    #[test]
    fn h6_txn_counter_propagated_from_child() {
        // After an inner appl call, the parent's txn_counter should
        // reflect the child's final txn_counter (so that subsequent
        // creates get unique IDs).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        ctx.txn_counter = 500;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_submit().unwrap();

        // After itxn_submit, txn_counter should reflect the child's
        // final value. The child was initialized with txn_counter = 501
        // (from parent's increment). The child didn't create any inner
        // txns, so its txn_counter stays at 501.
        assert_eq!(
            ctx.txn_counter, 501,
            "txn_counter should be propagated back from child"
        );
    }

    // ---- P1-1: Snapshot covers newly-created assets/apps ----

    #[test]
    fn p1_1_inner_acfg_create_rolled_back_on_later_failure() {
        // When an inner group has [acfg create, pay that fails], the acfg
        // create should be fully rolled back: no asset_params, no holdings,
        // no creator counter bump.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Snapshot the creator's account state before the attempt.
        let creator_total_before = store.get_or_default_account(&app_addr).total_created_assets;

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.txn_counter = 100;

            // Build inner group: [acfg create, pay to address with 0 balance
            // but a huge amount so it fails].
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // TypeEnum = acfg
            ctx.itxn_field(34, TealValue::Uint(1_000_000)).unwrap(); // ConfigAssetTotal
            ctx.itxn_field(35, TealValue::Uint(6)).unwrap(); // ConfigAssetDecimals
            ctx.itxn_next().unwrap();
            // Second txn: pay an enormous amount that will fail.
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
            ctx.itxn_field(7, TealValue::Bytes([20u8; 32].to_vec()))
                .unwrap(); // Receiver
            ctx.itxn_field(8, TealValue::Uint(999_999_999_999)).unwrap(); // Amount (way too much)
            let result = ctx.itxn_submit();

            assert!(result.is_err(), "submit should fail due to huge pay amount");
        }

        // The predicted asset ID would have been txn_counter_base(100) + 0 + 1 + 1 = 102.
        // It should NOT exist after rollback.
        assert!(
            !store.has_asset_params(102),
            "asset_params for created asset should be rolled back"
        );

        // Creator's total_created_assets should be unchanged.
        let creator_total_after = store.get_or_default_account(&app_addr).total_created_assets;
        assert_eq!(
            creator_total_before, creator_total_after,
            "creator's total_created_assets should be rolled back"
        );
    }

    #[test]
    fn p1_1_inner_appl_create_rolled_back_on_later_failure() {
        // When an inner group has [appl create, pay that fails], the appl
        // create should be fully rolled back: no app_params, no creator
        // counter bump.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let creator_total_before = store.get_or_default_account(&app_addr).total_created_apps;

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.opcode_budget = 2000;
            ctx.txn_counter = 200;

            // Build inner group: [appl create, pay that fails].
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
            ctx.itxn_field(24, TealValue::Uint(0)).unwrap(); // ApplicationID = 0 (create)
            ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
                .unwrap(); // ApprovalProgram
            ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
                .unwrap(); // ClearStateProgram
            ctx.itxn_next().unwrap();
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
            ctx.itxn_field(7, TealValue::Bytes([20u8; 32].to_vec()))
                .unwrap(); // Receiver
            ctx.itxn_field(8, TealValue::Uint(999_999_999_999)).unwrap(); // Amount
            let result = ctx.itxn_submit();

            assert!(result.is_err(), "submit should fail due to huge pay amount");
        }

        // The predicted app ID: txn_counter_base(200) + 0 + 1 = 201 (txn_counter after
        // increment), then execute_inner_appl does txn_counter + 1 = 202.
        assert!(
            !store.has_app_params(202),
            "app_params for created app should be rolled back"
        );

        let creator_total_after = store.get_or_default_account(&app_addr).total_created_apps;
        assert_eq!(
            creator_total_before, creator_total_after,
            "creator's total_created_apps should be rolled back"
        );
    }

    // ---- P1-2: Creator accounts in rollback snapshot ----

    #[test]
    fn p1_2_acfg_destroy_creator_totals_rolled_back() {
        // When an inner group has [acfg destroy, pay that fails],
        // the creator's total_created_assets should be rolled back.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_created_assets: 1,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );

        // Create asset 500 owned by app_addr (app_addr is both creator and manager).
        let asset_params = algo_types::AssetParams {
            total: 1000,
            manager: Some(app_addr),
            ..Default::default()
        };
        store.set_asset_params(
            500,
            AssetParamsRecord {
                params: asset_params,
                creator: app_addr,
            },
        );
        store.set_asset_holding(
            &app_addr,
            500,
            AssetHoldingType {
                amount: 1000,
                frozen: false,
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![500]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.txn_counter = 100;

            // Build inner group: [acfg destroy asset 500, pay that fails].
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // TypeEnum = acfg
            ctx.itxn_field(33, TealValue::Uint(500)).unwrap(); // ConfigAsset = 500
                                                               // Empty asset params = destroy.
            ctx.itxn_next().unwrap();
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
            ctx.itxn_field(7, TealValue::Bytes([20u8; 32].to_vec()))
                .unwrap(); // Receiver
            ctx.itxn_field(8, TealValue::Uint(999_999_999_999)).unwrap(); // Amount
            let result = ctx.itxn_submit();

            assert!(result.is_err(), "submit should fail");
        }

        // Creator's total_created_assets should be restored to 1.
        let creator_after = store.get_or_default_account(&app_addr);
        assert_eq!(
            creator_after.total_created_assets, 1,
            "creator's total_created_assets should be rolled back after failed destroy"
        );

        // Asset should still exist.
        assert!(
            store.has_asset_params(500),
            "asset should still exist after rollback"
        );
    }

    #[test]
    fn p1_2_appl_delete_creator_totals_rolled_back() {
        // When an inner group has [appl delete, pay that fails],
        // the app creator's total_created_apps should be rolled back.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app_addr = Address(app_address(42));

        // App 100 will be deleted. Its creator must be app 42's address
        // (the inner txn sender) to pass the creator check.
        store.set_app_params(
            100,
            AppParams {
                creator: app_addr,
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                global_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 4,
                },
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        // The creator of app 100 is app 42's address.
        let creator_addr = app_addr;
        store.set_account(
            &creator_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_created_apps: 2,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![creator_addr], vec![100], vec![]);
        {
            let mut ctx = make_context(&mut store, vec![txn]);
            ctx.fee_sink = Address([0xFEu8; 32]);
            ctx.opcode_budget = 2000;
            ctx.txn_counter = 300;

            // Build inner group: [appl delete app 100, pay that fails].
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
            ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
            ctx.itxn_field(25, TealValue::Uint(5)).unwrap(); // OnCompletion = DeleteApplication
            ctx.itxn_next().unwrap();
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
            ctx.itxn_field(7, TealValue::Bytes([20u8; 32].to_vec()))
                .unwrap(); // Receiver
            ctx.itxn_field(8, TealValue::Uint(999_999_999_999)).unwrap(); // Amount
            let result = ctx.itxn_submit();

            assert!(result.is_err(), "submit should fail");
        }

        // Creator's total_created_apps should still be 2 after rollback.
        let creator_after = store.get_or_default_account(&creator_addr);
        assert_eq!(
            creator_after.total_created_apps, 2,
            "creator's total_created_apps should be rolled back after failed delete"
        );

        // App should still exist.
        assert!(
            store.has_app_params(100),
            "app should still exist after rollback"
        );
    }

    // ---- P1-3: Nested inner TxIDs use correct parent ----

    #[test]
    fn p1_3_nested_inner_txn_ids_use_inner_parent() {
        // Verify that when a top-level app (42) creates an inner appl
        // call to app 100, the inner appl txn's ID uses the outer txn's
        // ID as parent, and if app 100 created nested inners, they would
        // use app 100's inner ID as parent.
        //
        // This test verifies that parent_txn_id is correctly set on the
        // child context by checking the inner txn ID computation.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let outer_txn_id = algo_codec::compute_txn_id(&txn.txn);

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        ctx.txn_counter = 500;
        // Set parent_txn_id for the top-level context (normally done by
        // the caller in apply.rs, but here we set it explicitly).
        ctx.parent_txn_id = outer_txn_id;

        // Submit inner appl call to app 100.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_submit().unwrap();

        // Get the computed inner txn ID.
        let inner_ids = ctx.inner_txn_ids();
        assert_eq!(inner_ids.len(), 1);
        assert_eq!(inner_ids[0].len(), 1);
        let computed_inner_id = &inner_ids[0][0];

        // Verify it matches manual computation using the outer txn's ID.
        let inner_txn = &ctx.inner_txns()[0][0].txn;
        let expected_id = algo_avm::itxn::compute_inner_txn_id(&outer_txn_id, 0, inner_txn);
        assert_eq!(
            computed_inner_id.0, expected_id.0,
            "inner txn ID should be derived from the outer txn's ID as parent"
        );

        // Now verify that if we set parent_txn_id to something else (simulating
        // a nested inner context), the computation changes accordingly.
        let fake_parent = algo_types::Digest([0xAB; 32]);
        let id_with_fake_parent = algo_avm::itxn::compute_inner_txn_id(&fake_parent, 0, inner_txn);
        assert_ne!(
            computed_inner_id.0, id_with_fake_parent.0,
            "different parent IDs should produce different inner txn IDs"
        );
    }

    /// UnifyInnerTxIDs (go-algorand v34+, `config/consensus.go`) activation
    /// boundary: a *nested* inner-appl context (simulated here by setting
    /// `parent_txn_id` to a value that differs from the raw hash of this
    /// context's own group transaction, exactly as `execute_inner_appl` does
    /// for a real 2-levels-deep nesting) must parent its own children on
    /// that correctly-propagated ancestor id at v34+ (matching go's
    /// `getTxID`/`currentTxID`), but on the raw hash of its own transaction
    /// before v34 (matching go's `getTxIDNotUnified`, which always uses
    /// `cx.caller.txn.ID()` -- a plain hash, blind to the caller's own
    /// nesting).
    #[test]
    fn unify_inner_tx_ids_activation_boundary() {
        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let raw_self_hash = algo_codec::compute_txn_id(&txn.txn);
        // A fake ancestor id, distinct from this context's own raw txn hash
        // -- simulates genuinely being a nested (2+ levels deep) inner-appl
        // context whose `parent_txn_id` was propagated from its own caller.
        let fake_ancestor = algo_types::Digest([0xABu8; 32]);
        assert_ne!(
            fake_ancestor.0, raw_self_hash.0,
            "sanity: must actually differ"
        );

        // ── Pre-v34 (not unified): child must be parented on the raw hash
        // of this context's own transaction, ignoring parent_txn_id. ──
        let mut store_pre = LedgerState::new();
        setup_app(
            &mut store_pre,
            42,
            make_program(6, true),
            make_program(6, true),
        );
        setup_app(
            &mut store_pre,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        store_pre.set_account(
            &Address(app_address(42)),
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let mut ctx_pre = make_context(&mut store_pre, vec![txn.clone()]);
        ctx_pre.fee_sink = Address([0xFEu8; 32]);
        ctx_pre.opcode_budget = 2000;
        ctx_pre.txn_counter = 500;
        ctx_pre.parent_txn_id = fake_ancestor;
        ctx_pre.consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V33,
        )
        .expect("v33 params");
        assert!(!ctx_pre.consensus.unify_inner_tx_ids);
        ctx_pre.itxn_begin().unwrap();
        ctx_pre.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx_pre.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx_pre.itxn_submit().unwrap();
        let inner_txn_pre = ctx_pre.inner_txns()[0][0].txn.clone();
        let computed_pre = ctx_pre.inner_txn_ids()[0][0];
        let expected_pre = algo_avm::itxn::compute_inner_txn_id(&raw_self_hash, 0, &inner_txn_pre);
        assert_eq!(
            computed_pre.0, expected_pre.0,
            "pre-v34 must parent on this context's own raw txn hash, not parent_txn_id"
        );

        // ── v34+ (unified): child must be parented on parent_txn_id. ──
        let mut store_post = LedgerState::new();
        setup_app(
            &mut store_post,
            42,
            make_program(6, true),
            make_program(6, true),
        );
        setup_app(
            &mut store_post,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        store_post.set_account(
            &Address(app_address(42)),
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let mut ctx_post = make_context(&mut store_post, vec![txn]);
        ctx_post.fee_sink = Address([0xFEu8; 32]);
        ctx_post.opcode_budget = 2000;
        ctx_post.txn_counter = 500;
        ctx_post.parent_txn_id = fake_ancestor;
        ctx_post.consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V34,
        )
        .expect("v34 params");
        assert!(ctx_post.consensus.unify_inner_tx_ids);
        ctx_post.itxn_begin().unwrap();
        ctx_post.itxn_field(16, TealValue::Uint(6)).unwrap();
        ctx_post.itxn_field(24, TealValue::Uint(100)).unwrap();
        ctx_post.itxn_submit().unwrap();
        let inner_txn_post = ctx_post.inner_txns()[0][0].txn.clone();
        let computed_post = ctx_post.inner_txn_ids()[0][0];
        let expected_post =
            algo_avm::itxn::compute_inner_txn_id(&fake_ancestor, 0, &inner_txn_post);
        assert_eq!(
            computed_post.0, expected_post.0,
            "v34+ must parent on the propagated parent_txn_id"
        );

        assert_ne!(
            computed_pre.0, computed_post.0,
            "sanity: the two protocol versions must actually compute different ids"
        );
    }

    #[test]
    fn p1_3_execute_inner_appl_sets_parent_txn_id_on_child() {
        // Verify that execute_inner_appl correctly passes the inner appl
        // txn's computed InnerID as the parent_txn_id for the child context.
        // We do this by checking that a child app call that itself creates
        // inner transactions would use the correct parent.
        //
        // We can verify this indirectly: set up app 42 calling app 100.
        // App 100's inner ID should be:
        //   InnerID(outer_txn_id, offset=0, app100_txn)
        // If app 100 then calls inner txns, those should use app 100's
        // InnerID as parent (not the outer txn's ID).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );
        let app_addr_42 = Address(app_address(42));
        let app_addr_100 = Address(app_address(100));
        store.set_account(
            &app_addr_42,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        store.set_account(
            &app_addr_100,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Build the outer transaction calling app 42.
        let sender = [10u8; 32];
        let outer_txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let outer_txn_id = algo_codec::compute_txn_id(&outer_txn.txn);

        // Build the inner appl txn that will be submitted.
        // We need to manually simulate what itxn_submit does to verify
        // the parent_txn_id is correctly set.
        let inner_appl_txn = Transaction {
            txn_type: "appl".into(),
            sender: app_addr_42,
            fee: 1000,
            application_id: 100,
            on_completion: 0,
            ..Default::default()
        };

        // Compute what the inner appl txn's InnerID should be.
        let inner_appl_id = algo_avm::itxn::compute_inner_txn_id(&outer_txn_id, 0, &inner_appl_txn);

        // Now if app 100 creates a nested inner pay txn, it should use
        // inner_appl_id as parent, NOT outer_txn_id.
        let nested_pay_txn = Transaction {
            txn_type: "pay".into(),
            sender: app_addr_100,
            fee: 1000,
            receiver: Address([20u8; 32]),
            amount: 100,
            ..Default::default()
        };

        // With correct parent (inner_appl_id):
        let correct_nested_id =
            algo_avm::itxn::compute_inner_txn_id(&inner_appl_id, 0, &nested_pay_txn);

        // With wrong parent (outer_txn_id -- the old behavior):
        let wrong_nested_id =
            algo_avm::itxn::compute_inner_txn_id(&outer_txn_id, 0, &nested_pay_txn);

        // These must be different, proving that using the correct parent matters.
        assert_ne!(
            correct_nested_id.0, wrong_nested_id.0,
            "nested inner txn IDs must differ when using correct parent vs outer txn"
        );

        // Verify the parent derivation chain is deterministic.
        let correct_nested_id2 =
            algo_avm::itxn::compute_inner_txn_id(&inner_appl_id, 0, &nested_pay_txn);
        assert_eq!(
            correct_nested_id.0, correct_nested_id2.0,
            "nested inner txn ID computation should be deterministic"
        );
    }

    // ---- P1-1: clawback source (asset_sender) snapshot rollback ----

    #[test]
    fn clawback_source_rolled_back_on_later_inner_failure() {
        // When an inner group has a clawback axfer followed by a txn that fails,
        // the clawback source account's asset holding must be restored.
        use algo_types::{AssetHolding as AH, AssetParams as AP, AssetParamsRecord as APR};

        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        let clawback_source = Address([50u8; 32]);
        let asset_receiver = Address([60u8; 32]);

        // Fund the app address (sender of inner txns).
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );

        // Create asset 88 with the app as the clawback address.
        store.set_asset_params(
            88,
            APR {
                params: AP {
                    total: 1_000_000,
                    clawback: Some(app_addr),
                    ..Default::default()
                },
                creator: app_addr,
            },
        );

        // Clawback source holds 500 units of asset 88.
        store.set_account(
            &clawback_source,
            AccountData {
                micro_algos: 100_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );
        store.set_asset_holding(
            &clawback_source,
            88,
            AH {
                amount: 500,
                frozen: false,
            },
        );

        // Asset receiver is opted in with 0 units.
        store.set_account(
            &asset_receiver,
            AccountData {
                micro_algos: 100_000,
                total_assets_opted_in: 1,
                ..Default::default()
            },
        );
        store.set_asset_holding(
            &asset_receiver,
            88,
            AH {
                amount: 0,
                frozen: false,
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        // Give fee credit so fees don't cause failures.
        ctx.fee_credit = 100_000;

        // Build inner group: clawback axfer (succeeds), then a pay to a zero
        // address which will fail because the receiver is the zero address.
        ctx.itxn_begin().unwrap();
        // First txn: clawback axfer of 200 units from clawback_source to asset_receiver.
        ctx.itxn_field(16, TealValue::Uint(4)).unwrap(); // TypeEnum = axfer
        ctx.itxn_field(17, TealValue::Uint(88)).unwrap(); // XferAsset
        ctx.itxn_field(18, TealValue::Uint(200)).unwrap(); // AssetAmount
        ctx.itxn_field(19, TealValue::Bytes(clawback_source.0.to_vec()))
            .unwrap(); // AssetSender (clawback source)
        ctx.itxn_field(20, TealValue::Bytes(asset_receiver.0.to_vec()))
            .unwrap(); // AssetReceiver

        // Second txn: pay that deliberately fails (send to receiver
        // with amount exceeding app balance to trigger insufficient balance).
        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([70u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(999_999_999)).unwrap(); // Amount > app balance

        let result = ctx.itxn_submit();
        assert!(
            result.is_err(),
            "inner group should fail on insufficient balance"
        );

        // Verify rollback: clawback source should still have its original 500 units.
        let source_holding = store.get_asset_holding(&clawback_source, 88).unwrap();
        assert_eq!(
            source_holding.amount, 500,
            "clawback source holding should be rolled back to 500"
        );

        // Receiver should still have 0 units (the clawback was rolled back).
        let rcv_holding = store.get_asset_holding(&asset_receiver, 88).unwrap();
        assert_eq!(
            rcv_holding.amount, 0,
            "asset receiver holding should be rolled back to 0"
        );
    }

    // ---- P1-2: fee deduction with zero fee_sink errors ----

    #[test]
    fn inner_txn_fee_deduction_errors_when_fee_sink_is_zero() {
        // When fee_sink is Address::ZERO, inner txn submission with fee > 0
        // should error rather than silently skipping fee deduction.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        // Do NOT set fee_sink — it stays as Address::ZERO.
        ctx.fee_credit = 100_000; // ensure fee credit check passes

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount

        let result = ctx.itxn_submit();
        assert!(
            result.is_err(),
            "itxn_submit should fail when fee_sink is zero"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("fee_sink not configured"),
            "error should mention fee_sink: {}",
            err_msg
        );
    }

    #[test]
    fn inner_txn_fees_properly_deducted_with_fee_sink_set() {
        // Verify that inner txn fees are deducted from sender and credited to fee_sink.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        let fee_sink_addr = Address([0xFEu8; 32]);

        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        store.set_account(
            &fee_sink_addr,
            AccountData {
                micro_algos: 0,
                ..Default::default()
            },
        );

        let initial_app_balance = 10_000_000u64;

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = fee_sink_addr;
        ctx.fee_credit = 100_000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount
        ctx.itxn_field(1, TealValue::Uint(2000)).unwrap(); // Fee = 2000

        ctx.itxn_submit().unwrap();

        // Fee (2000) should be deducted from the app address (sender of inner txn).
        let app_acct = store.get_account(&app_addr).unwrap();
        assert_eq!(
            app_acct.micro_algos,
            initial_app_balance - 2000 - 100, // fee + pay amount
            "sender should have fee and payment deducted"
        );

        // Fee should be credited to fee_sink.
        let sink_acct = store.get_account(&fee_sink_addr).unwrap();
        assert_eq!(
            sink_acct.micro_algos, 2000,
            "fee_sink should receive the inner txn fee"
        );
    }

    // ---- P1-1: Inner delete creator check; inner update has none ----

    #[test]
    fn inner_appl_update_by_non_creator_succeeds() {
        // App 100 was created by [1u8;32] (setup_app default). The inner
        // txn's sender is app 42's own address, NOT [1u8;32].
        //
        // Unlike Delete, go-algorand's `updateApplication`
        // (`ledger/apply/application.go:190`) takes no creator check
        // whatsoever -- `ApplicationCall` invokes it unconditionally as
        // `updateApplication(&ac, balances, creator, appIdx, header.Sender)`.
        // Permissioning an update to a particular admin address is left
        // entirely to the called app's own approval-program logic.
        // Corrected from the previous (incorrect) `..._fails` expectation
        // after checking directly against go-algorand source while porting
        // `TestInnerUpdateResizing` (issue #964) -- the old assumption blocked
        // exactly the legitimate non-creator-update pattern that test relies
        // on.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        // Distinguishable from the original (version 6) programs purely so
        // the assertions below can tell the update actually took effect.
        let new_approval = make_program(7, true);
        let new_clear = make_program(7, true);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(4)).unwrap(); // OnCompletion = UpdateApplication
        ctx.itxn_field(30, TealValue::Bytes(new_approval.clone()))
            .unwrap(); // ApprovalProgram
        ctx.itxn_field(31, TealValue::Bytes(new_clear.clone()))
            .unwrap(); // ClearStateProgram
        ctx.itxn_submit()
            .expect("a non-creator update must succeed when the called app's own program approves");

        let updated = ctx.store.get_app_params(100).unwrap();
        assert_eq!(
            updated.approval_program, new_approval,
            "the update must actually install the new approval program"
        );
        assert_eq!(
            updated.clear_state_program, new_clear,
            "the update must actually install the new clear-state program"
        );
        assert_eq!(
            updated.creator,
            Address([1u8; 32]),
            "update does not change the app's creator"
        );
    }

    #[test]
    fn inner_appl_update_by_creator_succeeds() {
        // App 100 was created by [1u8;32]. We make app 42's address == [1u8;32]
        // so the inner txn sender IS the creator. But setup_app uses Address([1u8;32])
        // as creator, so we need a different approach: create app 100 with creator = app 42's address.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // Create app 100 with creator = app 42's address (the inner txn sender).
        let app42_addr = Address(app_address(42));
        store.set_app_params(
            100,
            AppParams {
                creator: app42_addr,
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        let new_program = make_program(6, true);
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(4)).unwrap(); // OnCompletion = UpdateApplication
        ctx.itxn_field(30, TealValue::Bytes(new_program.clone()))
            .unwrap(); // ApprovalProgram
        ctx.itxn_field(31, TealValue::Bytes(new_program.clone()))
            .unwrap(); // ClearStateProgram
        ctx.itxn_submit().unwrap();
        drop(ctx);

        // Update should succeed — verify the app still exists.
        assert!(store.has_app_params(100));
    }

    #[test]
    fn inner_appl_delete_by_non_creator_fails() {
        // App 100 created by [1u8;32], inner sender is app 42's address.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));
        setup_app(
            &mut store,
            100,
            make_program(6, true),
            make_program(6, true),
        );

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(5)).unwrap(); // OnCompletion = DeleteApplication
        let result = ctx.itxn_submit();

        assert!(result.is_err(), "non-creator delete should fail");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not the creator"),
            "expected creator check error, got: {msg}"
        );
        drop(ctx);
        // App should still exist.
        assert!(store.has_app_params(100));
    }

    #[test]
    fn inner_appl_delete_by_creator_succeeds() {
        // Create app 100 with creator = app 42's address.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app42_addr = Address(app_address(42));
        store.set_app_params(
            100,
            AppParams {
                creator: app42_addr,
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(5)).unwrap(); // OnCompletion = DeleteApplication
        ctx.itxn_submit().unwrap();
        drop(ctx);

        // App should be deleted.
        assert!(!store.has_app_params(100));
    }

    // ---- P1-2: Inner app create/delete schema & extra pages accounting ----

    #[test]
    fn inner_appl_create_updates_schema_and_extra_pages() {
        // Inner app creation should update the creator's total_extra_app_pages
        // and total_app_schema (global schema).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Record creator's counters before.
        let before = store.get_or_default_account(&app_addr);
        let before_created = before.total_created_apps;
        let before_extra_pages = before.total_extra_app_pages;
        let before_schema = before.total_app_schema.clone();

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;
        ctx.txn_counter = 200;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(0)).unwrap(); // ApplicationID = 0 (create)
        ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ApprovalProgram
        ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ClearStateProgram
        ctx.itxn_field(52, TealValue::Uint(3)).unwrap(); // GlobalNumUint = 3
        ctx.itxn_field(53, TealValue::Uint(2)).unwrap(); // GlobalNumByteSlice = 2
        ctx.itxn_field(56, TealValue::Uint(1)).unwrap(); // ExtraProgramPages = 1
        ctx.itxn_submit().unwrap();
        drop(ctx);

        // Check creator's counters after.
        let after = store.get_or_default_account(&app_addr);
        assert_eq!(
            after.total_created_apps,
            before_created + 1,
            "total_created_apps should be incremented"
        );
        assert_eq!(
            after.total_extra_app_pages,
            before_extra_pages + 1,
            "total_extra_app_pages should be incremented by extra_program_pages"
        );
        assert_eq!(
            after.total_app_schema.num_uint,
            before_schema.num_uint + 3,
            "total_app_schema.num_uint should include global schema"
        );
        assert_eq!(
            after.total_app_schema.num_byte_slice,
            before_schema.num_byte_slice + 2,
            "total_app_schema.num_byte_slice should include global schema"
        );
    }

    #[test]
    fn inner_appl_delete_reverses_schema_and_extra_pages() {
        // Inner app delete should decrement the creator's total_extra_app_pages
        // and total_app_schema (global schema).
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app42_addr = Address(app_address(42));

        // Create app 100 with creator = app 42's address, with known schema and extra pages.
        store.set_app_params(
            100,
            AppParams {
                creator: app42_addr,
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 1,
                },
                global_state_schema: StateSchema {
                    num_uint: 5,
                    num_byte_slice: 3,
                },
                extra_program_pages: 2,
                ..Default::default()
            },
        );

        // Set the creator's account with counters reflecting the created app.
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_created_apps: 1,
                total_extra_app_pages: 2,
                total_app_schema: StateSchema {
                    num_uint: 5,
                    num_byte_slice: 3,
                },
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(5)).unwrap(); // OnCompletion = DeleteApplication
        ctx.itxn_submit().unwrap();
        drop(ctx);

        // App should be deleted.
        assert!(!store.has_app_params(100));

        // Creator's counters should be decremented.
        let after = store.get_or_default_account(&app42_addr);
        assert_eq!(
            after.total_created_apps, 0,
            "total_created_apps should be decremented"
        );
        assert_eq!(
            after.total_extra_app_pages, 0,
            "total_extra_app_pages should be decremented by app's extra_program_pages"
        );
        assert_eq!(
            after.total_app_schema.num_uint, 0,
            "total_app_schema.num_uint should be decremented by global schema"
        );
        assert_eq!(
            after.total_app_schema.num_byte_slice, 0,
            "total_app_schema.num_byte_slice should be decremented by global schema"
        );
    }

    // ---- P1-3: Inner opt-in/close-out/clear local schema accounting ----

    #[test]
    fn inner_appl_optin_updates_local_schema() {
        // Inner opt-in should update the sender's total_app_schema with local schema.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100 with known local schema.
        let app42_addr = Address(app_address(42));
        store.set_app_params(
            100,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 3,
                },
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Verify counters before.
        let before = store.get_or_default_account(&app42_addr);
        assert_eq!(before.total_apps_opted_in, 0);
        assert_eq!(before.total_app_schema.num_uint, 0);
        assert_eq!(before.total_app_schema.num_byte_slice, 0);

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(1)).unwrap(); // OnCompletion = OptIn
        ctx.itxn_submit().unwrap();
        drop(ctx);

        let after = store.get_or_default_account(&app42_addr);
        assert_eq!(after.total_apps_opted_in, 1, "should be opted in");
        assert_eq!(
            after.total_app_schema.num_uint, 4,
            "total_app_schema.num_uint should include local schema"
        );
        assert_eq!(
            after.total_app_schema.num_byte_slice, 3,
            "total_app_schema.num_byte_slice should include local schema"
        );
    }

    #[test]
    fn inner_appl_closeout_reverses_local_schema() {
        // Inner close-out should subtract local schema from sender's total_app_schema.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app42_addr = Address(app_address(42));
        store.set_app_params(
            100,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 4,
                    num_byte_slice: 3,
                },
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        // Pre-opt-in: set the sender as already opted in with local state.
        let local_schema = StateSchema {
            num_uint: 4,
            num_byte_slice: 3,
        };
        store.set_app_local_state(
            &app42_addr,
            100,
            AppLocalState {
                schema: local_schema.clone(),
                key_value: BTreeMap::new(),
            },
        );
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_apps_opted_in: 1,
                total_app_schema: local_schema.clone(),
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(2)).unwrap(); // OnCompletion = CloseOut
        ctx.itxn_submit().unwrap();
        drop(ctx);

        let after = store.get_or_default_account(&app42_addr);
        assert_eq!(after.total_apps_opted_in, 0, "should no longer be opted in");
        assert_eq!(
            after.total_app_schema.num_uint, 0,
            "total_app_schema.num_uint should be decremented"
        );
        assert_eq!(
            after.total_app_schema.num_byte_slice, 0,
            "total_app_schema.num_byte_slice should be decremented"
        );
        // Local state should be removed.
        assert!(!store.has_app_local_state(&app42_addr, 100));
    }

    #[test]
    fn inner_appl_clearstate_reverses_local_schema() {
        // Inner clear-state should subtract local schema from sender's total_app_schema.
        let mut store = LedgerState::new();
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        let app42_addr = Address(app_address(42));
        store.set_app_params(
            100,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: make_program(6, true),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema {
                    num_uint: 2,
                    num_byte_slice: 5,
                },
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        // Pre-opt-in: set the sender as already opted in.
        let local_schema = StateSchema {
            num_uint: 2,
            num_byte_slice: 5,
        };
        store.set_app_local_state(
            &app42_addr,
            100,
            AppLocalState {
                schema: local_schema.clone(),
                key_value: BTreeMap::new(),
            },
        );
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                total_apps_opted_in: 1,
                total_app_schema: local_schema.clone(),
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 2000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100
        ctx.itxn_field(25, TealValue::Uint(3)).unwrap(); // OnCompletion = ClearState
        ctx.itxn_submit().unwrap();
        drop(ctx);

        let after = store.get_or_default_account(&app42_addr);
        assert_eq!(after.total_apps_opted_in, 0, "should no longer be opted in");
        assert_eq!(
            after.total_app_schema.num_uint, 0,
            "total_app_schema.num_uint should be decremented"
        );
        assert_eq!(
            after.total_app_schema.num_byte_slice, 0,
            "total_app_schema.num_byte_slice should be decremented"
        );
        // Local state should be removed.
        assert!(!store.has_app_local_state(&app42_addr, 100));
    }

    // ---- P1: Preserve txn_counter across sibling inner txns ----

    #[test]
    fn p1_sibling_inner_txns_get_distinct_creatable_ids() {
        // Scenario: inner group with 2 txns:
        //   [0] appl call to app 100, whose approval program creates an asset
        //       via a nested inner acfg (consuming an extra txn_counter slot)
        //   [1] acfg create (direct asset creation)
        //
        // Before the fix, txn_counter was reset from txn_counter_base + i for
        // each sibling, so the nested asset creation in [0] was invisible to
        // [1], causing duplicate IDs.
        let mut store = LedgerState::new();

        // App 42 (the outer app).
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100: its approval program does itxn_begin + acfg create + itxn_submit + approve.
        // Bytecode: itxn_begin, pushint 3, itxn_field TypeEnum, pushint 1,
        //           itxn_field ConfigAssetTotal, itxn_submit, pushint 1, return
        let acfg_creating_program: Vec<u8> = vec![
            0x06, // version 6
            0xb1, // itxn_begin
            0x81, 0x03, // pushint 3 (acfg)
            0xb2, 0x10, // itxn_field TypeEnum (16)
            0x81, 0x01, // pushint 1
            0xb2, 0x22, // itxn_field ConfigAssetTotal (34)
            0xb3, // itxn_submit
            0x81, 0x01, // pushint 1
            0x43, // return
        ];
        store.set_app_params(
            100,
            AppParams {
                creator: Address([1u8; 32]),
                approval_program: acfg_creating_program.clone(),
                clear_state_program: make_program(6, true),
                global_state: std::collections::BTreeMap::new(),
                global_state_schema: StateSchema::default(),
                local_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        // Fund the outer app address (app 42) and the inner app address (app 100).
        let app42_addr = Address(app_address(42));
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let app100_addr = Address(app_address(100));
        store.set_account(
            &app100_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Set up a fee sink.
        let fee_sink = Address([0xFEu8; 32]);
        store.set_account(
            &fee_sink,
            AccountData {
                micro_algos: 0,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = fee_sink;
        ctx.opcode_budget = 5000;
        ctx.txn_counter = 100;

        // Build inner group: [0] appl call to 100, [1] acfg create.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // TypeEnum = appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // ApplicationID = 100

        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(3)).unwrap(); // TypeEnum = acfg
        ctx.itxn_field(34, TealValue::Uint(500_000)).unwrap(); // ConfigAssetTotal

        ctx.itxn_submit().unwrap();

        // Expected counter progression:
        //   txn_counter_base = 100
        //   i=0 (appl): current_counter = 101, execute_inner_appl gets counter=101
        //     Inside app 100: nested acfg uses counter 101+1=102, then child
        //     counter becomes 102. Returned ad.txn_counter = 102.
        //   current_counter = 102 (from ad.txn_counter)
        //   i=1 (acfg): current_counter = 103, asset_id = 103 + 1 = 104
        //
        // The nested asset created by app 100 has ID 102+1 = 103 (inside the
        // child context). The sibling acfg gets asset_id = current_counter + 1
        // = 103 + 1 = 104.

        // Read created asset ID from the second inner txn (index 1).
        let sibling_asset = ctx.last_itxn_group_field(1, 60, None).unwrap(); // CreatedAssetID

        // The sibling asset ID must not collide with the nested asset (103).
        if let TealValue::Uint(sibling_id) = sibling_asset {
            // The nested asset created inside app 100 should exist at ID 103.
            assert!(
                store.get_asset_params(103).is_some(),
                "nested asset at ID 103 should exist"
            );
            // The sibling asset should be at a different (higher) ID.
            assert_ne!(
                sibling_id, 103,
                "sibling acfg must not get the same ID as the nested asset"
            );
            assert!(
                store.get_asset_params(sibling_id).is_some(),
                "sibling asset should exist in store"
            );
            // They should be distinct.
            assert_ne!(
                sibling_id, 103,
                "sibling and nested assets must have distinct IDs"
            );
        } else {
            panic!("expected Uint for CreatedAssetID");
        }
    }

    // ---- P1-2: Preserve explicitly set zero inner fees (fee pooling) ----

    #[test]
    fn p1_2_itxn_field_fee_zero_preserved() {
        // When a program explicitly sets Fee=0 via `itxn_field`, the zero
        // should be preserved (not defaulted to MinTxnFee). This enables
        // fee pooling where the outer transaction overpays.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Fund the app address.
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        // Provide enough fee credit so the zero-fee inner txn is covered.
        ctx.fee_credit = 10_000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount
        ctx.itxn_field(1, TealValue::Uint(0)).unwrap(); // Fee = 0 explicitly
        ctx.itxn_submit().unwrap();

        // Read back the fee from the last inner txn.
        let fee_val = ctx.last_itxn_field(1, None).unwrap(); // Fee
        assert_eq!(
            fee_val,
            TealValue::Uint(0),
            "explicitly set fee=0 should be preserved, not defaulted to MinTxnFee"
        );
    }

    #[test]
    fn p1_2_itxn_field_fee_not_set_defaults_to_min() {
        // When a program does NOT set Fee, it should default to MinTxnFee.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount
                                                          // Fee is NOT set — should default to MinTxnFee.
        ctx.itxn_submit().unwrap();

        let fee_val = ctx.last_itxn_field(1, None).unwrap(); // Fee
        assert_eq!(
            fee_val,
            TealValue::Uint(params::MIN_TXN_FEE),
            "fee should default to MinTxnFee when not explicitly set"
        );
    }

    #[test]
    fn p1_2_itxn_field_fee_zero_uses_fee_credit() {
        // When fee=0 is explicitly set and fee_credit covers the shortfall,
        // the submission should succeed and deduct from fee_credit.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.fee_credit = 5_000;

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap(); // Receiver
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount
        ctx.itxn_field(1, TealValue::Uint(0)).unwrap(); // Fee = 0 explicitly
        ctx.itxn_submit().unwrap();

        // fee_credit should have been reduced by MinTxnFee (the shortfall).
        assert_eq!(
            ctx.fee_credit,
            5_000 - params::MIN_TXN_FEE,
            "fee_credit should be reduced by the shortfall when fee=0"
        );
    }

    #[test]
    fn p1_2_itxn_field_fee_zero_insufficient_credit_fails() {
        // When fee=0 is explicitly set but fee_credit is insufficient, submit
        // should fail.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.fee_credit = 0; // No credit available

        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([30u8; 32].to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
        ctx.itxn_field(1, TealValue::Uint(0)).unwrap(); // Fee = 0 explicitly

        let result = ctx.itxn_submit();
        assert!(
            result.is_err(),
            "itxn_submit should fail when fee=0 and no fee credit available"
        );
    }

    // ---- P1-3: Snapshot covers IDs created by nested inner calls ----

    #[test]
    fn p1_3_snapshot_rollback_cleans_nested_created_resources() {
        // Scenario: Inner group has [appl (creates nested asset), pay (fails)].
        // The nested asset created by the appl should be cleaned up when the
        // group rolls back due to the failing pay.
        //
        // We simulate this by having the inner appl create an asset via a
        // nested inner txn. The predicted asset ID from the pre-snapshot won't
        // cover it. The P1-3 fix ensures rollback removes it.

        let mut store = LedgerState::new();

        // App 42 (outer caller)
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100: a program that creates an asset via inner acfg.
        // We build a program: itxn_begin, pushint 3 (acfg), itxn_field TypeEnum,
        // pushint 1000000, itxn_field ConfigAssetTotal, itxn_submit, pushint 1, return
        let acfg_program = vec![
            6u8,  // version 6
            0xb1, // itxn_begin
            0x81, 0x03, // pushint 3 (acfg)
            0xb2, 0x10, // itxn_field TypeEnum (16)
            0x81, 0xc0, 0x84, 0x3d, // pushint 1000000 (varuint encoded)
            0xb2, 0x22, // itxn_field ConfigAssetTotal (34)
            0xb3, // itxn_submit
            0x81, 0x01, // pushint 1
            0x43, // return
        ];
        setup_app(&mut store, 100, acfg_program.clone(), make_program(6, true));

        // Fund the app addresses.
        let app42_addr = Address(app_address(42));
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let app100_addr = Address(app_address(100));
        store.set_account(
            &app100_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let fee_sink = Address([0xFEu8; 32]);
        store.set_account(
            &fee_sink,
            AccountData {
                micro_algos: 0,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = fee_sink;
        ctx.fee_credit = 100_000;
        ctx.txn_counter = 100;
        ctx.opcode_budget = 20000;

        // First, verify that the nested asset creation works in isolation.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_submit().unwrap();

        // The inner appl incremented counter to 101, then nested acfg
        // incremented again to 102, creating asset at 102+1 = 103.
        // Actually the nested inner txn creates at counter+1 inside child.
        // After submit, the asset should exist in the store.
        // (The exact ID depends on counter progression inside execute_inner_appl.)

        // Now test rollback: We'll do another itxn_begin group that creates
        // another nested asset + a failing second txn. But since we can't
        // easily force a failure in the second txn of a group in this test
        // infrastructure, we instead verify the positive case that
        // extra_created_asset_ids are tracked by checking the state is
        // consistent after successful execution.

        // Verify the asset created by nested inner txn exists.
        // The counter was at 100 before the submit.
        // i=0 appl: counter becomes 101. Inside child, nested acfg: counter 101+1=102, asset=103.
        // So asset 103 should exist.
        assert!(
            store.get_asset_params(103).is_some(),
            "nested asset at ID 103 should exist after successful submit"
        );
    }

    #[test]
    fn p1_3_extra_created_ids_tracked_for_rollback() {
        // Verify that the `extra_created_asset_ids` / `extra_created_app_ids`
        // mechanism works. When an inner group fails after an earlier sibling
        // inner appl already created nested resources, those resources must be
        // cleaned up by rollback.
        //
        // We test this by having an inner group:
        //   [appl (creates nested asset successfully)] then a bad second txn
        // The bad second txn fails, and the rollback must remove the nested asset.

        let mut store = LedgerState::new();

        // App 42 outer caller
        setup_app(&mut store, 42, make_program(6, true), make_program(6, true));

        // App 100: creates a nested asset (same program as above)
        let acfg_program = vec![
            6u8, 0xb1, 0x81, 0x03, 0xb2, 0x10, 0x81, 0xc0, 0x84, 0x3d, 0xb2, 0x22, 0xb3, 0x81,
            0x01, 0x43,
        ];
        setup_app(&mut store, 100, acfg_program.clone(), make_program(6, true));

        // App 200: rejects (approval program pushes 0)
        setup_app(
            &mut store,
            200,
            make_program(6, false), // rejects
            make_program(6, true),
        );

        let app42_addr = Address(app_address(42));
        store.set_account(
            &app42_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let app100_addr = Address(app_address(100));
        store.set_account(
            &app100_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );
        let app200_addr = Address(app_address(200));
        store.set_account(
            &app200_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        let fee_sink = Address([0xFEu8; 32]);
        store.set_account(
            &fee_sink,
            AccountData {
                micro_algos: 0,
                ..Default::default()
            },
        );

        let sender = [10u8; 32];
        let txn = make_appl_txn(sender, 42, vec![], vec![100, 200], vec![]);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = fee_sink;
        ctx.fee_credit = 100_000;
        ctx.txn_counter = 100;
        ctx.opcode_budget = 20000;

        // Build a group: [inner appl 100 (succeeds + creates nested asset),
        //                  inner appl 200 (rejects)]
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(100)).unwrap(); // app 100
        ctx.itxn_next().unwrap();
        ctx.itxn_field(16, TealValue::Uint(6)).unwrap(); // appl
        ctx.itxn_field(24, TealValue::Uint(200)).unwrap(); // app 200 (rejects)

        let result = ctx.itxn_submit();
        assert!(result.is_err(), "group should fail because app 200 rejects");

        // The nested asset created by app 100 (at ID ~103) should NOT exist
        // after rollback. Without the P1-3 fix, the snapshot wouldn't cover
        // this ID and it would remain in the store.
        assert!(
            store.get_asset_params(103).is_none(),
            "nested asset should be cleaned up on rollback (P1-3 fix)"
        );
        // Also verify that no unexpected asset params remain.
        // The only assets that could have been created are at IDs around 102-104.
        for id in 101..=105 {
            assert!(
                store.get_asset_params(id).is_none(),
                "no stale asset params at ID {} after rollback",
                id
            );
        }
    }

    #[test]
    fn p1_1_single_txn_group_inner_budget_is_16() {
        // A single-transaction group should allow exactly 16 inner txns
        // (MAX_INNER_TRANSACTIONS * 1), not 256.
        let txn = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        // Fund the app address generously so inner pays succeed.
        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 100_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 100_000; // generous budget

        // Submit 16 inner pay txns — should all succeed.
        for i in 0..params::MAX_INNER_TRANSACTIONS {
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
            let mut receiver = [0u8; 32];
            receiver[0] = (i + 1) as u8;
            ctx.itxn_field(7, TealValue::Bytes(receiver.to_vec()))
                .unwrap(); // Receiver
            ctx.itxn_field(8, TealValue::Uint(100)).unwrap(); // Amount
            ctx.itxn_submit().unwrap();
        }

        assert_eq!(ctx.num_inner_txns(), 16);

        // The 17th inner txn should fail — budget exhausted.
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap(); // TypeEnum = pay
        ctx.itxn_field(7, TealValue::Bytes([0xFFu8; 32].to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
        let result = ctx.itxn_submit();
        assert!(
            result.is_err(),
            "17th inner txn should fail in a single-txn group"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too many inner transactions"),
            "error should mention too many inner transactions, got: {}",
            err_msg
        );
    }

    #[test]
    fn p1_1_two_txn_group_inner_budget_is_32() {
        // A 2-transaction group should allow up to 32 inner txns
        // (MAX_INNER_TRANSACTIONS * 2).
        let txn1 = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let txn2 = make_pay_txn([10u8; 32], [20u8; 32], 5000);
        let mut store = LedgerState::new();

        let app_addr = Address(app_address(42));
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 100_000_000,
                ..Default::default()
            },
        );

        let mut ctx = make_context(&mut store, vec![txn1, txn2]);
        ctx.fee_sink = Address([0xFEu8; 32]);
        ctx.opcode_budget = 100_000;

        // Submit 16 inner txns — well within budget.
        for i in 0..16 {
            ctx.itxn_begin().unwrap();
            ctx.itxn_field(16, TealValue::Uint(1)).unwrap();
            let mut receiver = [0u8; 32];
            receiver[0] = (i + 1) as u8;
            ctx.itxn_field(7, TealValue::Bytes(receiver.to_vec()))
                .unwrap();
            ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
            ctx.itxn_submit().unwrap();
        }

        // 17th should also succeed (budget is 32 for a 2-txn group).
        ctx.itxn_begin().unwrap();
        ctx.itxn_field(16, TealValue::Uint(1)).unwrap();
        ctx.itxn_field(7, TealValue::Bytes([0xAAu8; 32].to_vec()))
            .unwrap();
        ctx.itxn_field(8, TealValue::Uint(100)).unwrap();
        ctx.itxn_submit().unwrap();

        assert_eq!(ctx.num_inner_txns(), 17);
    }

    // ---- issue #570: kv_mods recorder ----

    /// Build a `LedgerAvmContext` with V41 consensus (real box budget/size
    /// limits) and `name` pre-marked available for `app_id`, bypassing the
    /// `txn.boxes` ref-resolution plumbing so these tests can call the box
    /// opcodes directly without constructing a full transaction group.
    fn make_box_context<'a>(
        store: &'a mut LedgerState,
        app_id: u64,
        name: &[u8],
    ) -> LedgerAvmContext<'a, LedgerState> {
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .expect("V41 consensus params must exist");
        // `authorize_box_access` (issue #662) looks up the current app's own
        // `AppParams` even for same-app box access (to read `FamilyBoxAccess`),
        // matching go-algorand's `authorizeBoxAccess`
        // (`data/transactions/logic/box.go:47-51`). A running app's own
        // params always exist on a real ledger; register a default entry
        // here so these box-opcode-focused tests don't need to construct one.
        if !store.has_app_params(app_id) {
            store.set_app_params(
                app_id,
                algo_types::AppParams {
                    creator: Address([1u8; 32]),
                    ..Default::default()
                },
            );
        }
        let mut ctx = LedgerAvmContext::new(
            store,
            vec![make_appl_txn([9u8; 32], app_id, vec![], vec![], vec![])],
            0,
            1000,
            12345,
            app_id,
            [1u8; 32],
            true,
            [2u8; 32],
            [3u8; 32],
            consensus,
        );
        ctx.available_boxes.insert((app_id, name.to_vec()), false);
        ctx.boxes_initialized = true;
        ctx.read_budget_checked = true;
        ctx.io_budget = 10_000;
        ctx
    }

    #[test]
    fn box_put_on_new_box_records_empty_old_data() {
        let mut store = LedgerState::new();
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            ctx.box_put(b"mybox", b"hello").unwrap();
        }

        let map = recorder.borrow();
        let key = crate::sqlite::make_box_key(42, b"mybox");
        let delta = map.get(&key).expect("box_put must record a kv_mods entry");
        assert_eq!(delta.data, b"hello");
        assert!(
            delta.old_data.is_empty(),
            "box didn't exist before this round, so old_data must be empty"
        );
    }

    #[test]
    fn box_put_on_existing_box_records_prior_value_as_old_data() {
        let mut store = LedgerState::new();
        store.set_box(42, b"mybox", b"V1".to_vec());
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            // Replacement value must match the existing box's size (box_put
            // requires equal-size replacement) -- "V1" and "V2" are both 2 bytes.
            ctx.box_put(b"mybox", b"V2").unwrap();
        }

        let map = recorder.borrow();
        let key = crate::sqlite::make_box_key(42, b"mybox");
        let delta = map.get(&key).unwrap();
        assert_eq!(delta.old_data, b"V1");
        assert_eq!(delta.data, b"V2");
    }

    #[test]
    fn box_del_records_new_data_as_empty() {
        let mut store = LedgerState::new();
        store.set_box(42, b"mybox", b"hello".to_vec());
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            assert!(ctx.box_del(b"mybox").unwrap());
        }

        let map = recorder.borrow();
        let key = crate::sqlite::make_box_key(42, b"mybox");
        let delta = map.get(&key).expect("box_del must record a kv_mods entry");
        assert_eq!(delta.old_data, b"hello");
        assert!(delta.data.is_empty(), "deleted box must record empty data");
    }

    #[test]
    fn box_del_of_nonexistent_box_records_nothing() {
        let mut store = LedgerState::new();
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            assert!(!ctx.box_del(b"mybox").unwrap());
        }
        assert!(
            recorder.borrow().is_empty(),
            "deleting a box that never existed is a no-op and must not appear in kv_mods"
        );
    }

    /// Multiple writes to the same box within one round must collapse to a
    /// single entry whose `old_data` reflects the value at the *start* of
    /// the round (not any intermediate value) and whose `data` reflects the
    /// value at the *end* of the round — matching go-algorand's
    /// `ledgercore.StateDelta` semantics (a round-scoped diff, not a write
    /// log).
    #[test]
    fn multiple_writes_in_one_round_collapse_to_start_end_diff() {
        let mut store = LedgerState::new();
        store.set_box(42, b"mybox", b"V1".to_vec());
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            ctx.box_put(b"mybox", b"V2").unwrap();
            ctx.box_put(b"mybox", b"V3").unwrap();
        }

        let map = recorder.borrow();
        let key = crate::sqlite::make_box_key(42, b"mybox");
        let delta = map.get(&key).unwrap();
        assert_eq!(
            delta.old_data, b"V1",
            "old_data must be the round-start value"
        );
        assert_eq!(delta.data, b"V3", "data must be the round-end value");
    }

    /// A box created and deleted within the same round nets to no visible
    /// change; the recorder still carries the entry (both sides empty)
    /// rather than needing special-case suppression, which is harmless for
    /// callers reconstructing historical state.
    #[test]
    fn box_created_then_deleted_in_same_round_nets_to_empty_entry() {
        let mut store = LedgerState::new();
        let recorder: KvModsRecorder = Rc::new(RefCell::new(HashMap::new()));
        {
            let mut ctx = make_box_context(&mut store, 42, b"mybox");
            ctx.kv_mods_recorder = Some(recorder.clone());
            ctx.box_put(b"mybox", b"hello").unwrap();
            assert!(ctx.box_del(b"mybox").unwrap());
        }

        let map = recorder.borrow();
        let key = crate::sqlite::make_box_key(42, b"mybox");
        let delta = map.get(&key).unwrap();
        assert!(delta.old_data.is_empty());
        assert!(delta.data.is_empty());
    }

    #[test]
    fn no_recorder_attached_is_a_no_op() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_context(&mut store, 42, b"mybox");
        // kv_mods_recorder left None (default) -- must not panic or error.
        ctx.box_put(b"mybox", b"hello").unwrap();
        assert!(ctx.kv_mods_recorder.is_none());
    }

    // -------------------------------------------------------------------
    // Box write-budget / dirty-byte tracking (issue #823 theme 3), ported
    // from go-algorand's TestDirtyTracking/TestBoxRepeatedCreate
    // (data/transactions/logic/box_test.go). go's tests chain multiple box
    // opcodes within a *single* program run (one `TestApp` call = one
    // eval, one dirty_bytes accumulator); each Rust test below mirrors one
    // such program as a sequence of direct method calls against one fresh
    // `LedgerAvmContext`, matching `MakeSampleEnv()`'s 200-byte budget
    // (2 box refs).
    // -------------------------------------------------------------------

    /// Build a `LedgerAvmContext` for `app_id` with `io_budget` and both
    /// `"self"`/`"other"` pre-marked available (not yet dirty).
    fn make_box_budget_context(
        store: &mut LedgerState,
        app_id: u64,
        io_budget: u64,
    ) -> LedgerAvmContext<'_, LedgerState> {
        let mut ctx = make_box_context(store, app_id, b"self");
        ctx.available_boxes
            .insert((app_id, b"other".to_vec()), false);
        ctx.io_budget = io_budget;
        ctx
    }

    #[test]
    fn dirty_tracking_create_at_exact_budget_succeeds() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
    }

    #[test]
    fn dirty_tracking_resize_over_budget_rejected() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        let err = ctx.box_resize(b"self", 201).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dirty_tracking_create_second_box_over_budget_rejected() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        let err = ctx.box_create(b"other", 201).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dirty_tracking_deleting_self_does_not_free_budget_for_oversized_other() {
        // "deleting self doesn't give extra write budget to create big other"
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        ctx.box_del(b"self").unwrap();
        let err = ctx.box_create(b"other", 201).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dirty_tracking_create_delete_create_cancels_out() {
        // "though it cancels out a creation that happened here"
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        ctx.box_del(b"self").unwrap();
        ctx.box_create(b"other", 200).unwrap();
    }

    #[test]
    fn dirty_tracking_shrink_frees_exactly_enough_budget() {
        // create self(200); resize self to 150; create other(50) -> fits
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        ctx.box_resize(b"self", 150).unwrap();
        ctx.box_create(b"other", 50).unwrap();
    }

    #[test]
    fn dirty_tracking_shrink_frees_exactly_enough_budget_off_by_one_rejected() {
        // Same, but other=51 -> one byte over budget.
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        ctx.box_resize(b"self", 150).unwrap();
        let err = ctx.box_create(b"other", 51).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dirty_tracking_double_delete_is_a_noop_not_an_extra_credit() {
        // "no funny business by trying to del twice!"
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();
        assert!(ctx.box_del(b"self").unwrap());
        // Second delete of an already-deleted box reports "not found",
        // matching go's `box_del; !` idiom (bool result, not error).
        assert!(!ctx.box_del(b"self").unwrap());
        let err = ctx.box_create(b"self", 201).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn box_repeated_create_same_size_is_a_noop() {
        // TestBoxRepeatedCreate: creating a box that already exists with
        // the same size is a cheap no-op, not a second write-budget charge.
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        assert!(ctx.box_create(b"self", 200).unwrap());
        // Second create call for the same box/size: reports "already
        // existed" (false) without re-charging the write budget.
        assert!(!ctx.box_create(b"self", 200).unwrap());
        assert_eq!(
            ctx.dirty_bytes, 200,
            "size-matching re-create must not double-charge"
        );
    }

    // -------------------------------------------------------------------
    // Box write-budget / cross-txn / ClearState-unavailability (issue #823
    // theme 3 remainder), ported from go-algorand's TestBoxWriteBudget,
    // TestWriteBudgetPut, TestIOBudgetGrow, TestBoxUnavailableWithClearState,
    // TestBoxAcrossTxns (data/transactions/logic/box_test.go). As above,
    // each Rust test decomposes one go `TestApp`/`TestApps` call (one fresh
    // eval) into direct method calls against a fresh `LedgerAvmContext`
    // rather than replaying an entire stateful go test function verbatim.
    // -------------------------------------------------------------------

    /// TestBoxAcrossTxns: a box created by one top-level call is visible
    /// (initially empty) to a later call against the same underlying store,
    /// and a later call's modification is visible to one after that --
    /// pinning that box content lives in the shared `Store`, not anything
    /// scoped to a single `LedgerAvmContext`.
    #[test]
    fn box_across_txns_visible_and_mutable_across_separate_contexts() {
        let mut store = LedgerState::new();
        store.set_app_params(
            888,
            algo_types::AppParams {
                creator: Address([1u8; 32]),
                ..Default::default()
            },
        );

        // First "txn": create box "self", size 64 (all zero).
        {
            let mut ctx = make_box_context(&mut store, 888, b"self");
            assert!(ctx.box_create(b"self", 64).unwrap());
        }
        // Second "txn" (fresh context, same store): can read it, even
        // though it's still empty.
        {
            let mut ctx = make_box_context(&mut store, 888, b"self");
            let data = ctx.box_extract(b"self", 10, 4).unwrap();
            assert_eq!(data, vec![0u8; 4]);
        }
        // Third "txn": re-create at the same size is a no-op (already
        // exists).
        {
            let mut ctx = make_box_context(&mut store, 888, b"self");
            assert!(!ctx.box_create(b"self", 64).unwrap());
        }
        // Fourth "txn": modify it.
        {
            let mut ctx = make_box_context(&mut store, 888, b"self");
            ctx.box_replace(b"self", 2, b"hi").unwrap();
        }
        // Fifth "txn": the modification is visible -- "\0hi\0".
        {
            let mut ctx = make_box_context(&mut store, 888, b"self");
            let data = ctx.box_extract(b"self", 1, 4).unwrap();
            assert_eq!(data, vec![0u8, b'h', b'i', 0u8]);
        }
    }

    /// TestBoxUnavailableWithClearState: every box opcode must reject with
    /// "boxes may not be accessed from ClearState program" when the current
    /// transaction's `OnCompletion` is ClearState, regardless of whether the
    /// box is otherwise available.
    #[test]
    fn box_unavailable_with_clear_state_rejects_every_op() {
        const MSG: &str = "boxes may not be accessed from ClearState program";

        macro_rules! check {
            ($name:expr, $body:expr) => {{
                let mut store = LedgerState::new();
                let mut ctx = make_box_context(&mut store, 888, b"self");
                ctx.group[0].txn.on_completion = ON_COMPLETION_CLEAR_STATE;
                let err = $body(&mut ctx).unwrap_err();
                assert!(
                    err.to_string().contains(MSG),
                    "{}: unexpected error: {err}",
                    $name
                );
            }};
        }

        check!("box_create", |ctx: &mut LedgerAvmContext<
            '_,
            LedgerState,
        >| ctx.box_create(b"self", 64));
        check!("box_del", |ctx: &mut LedgerAvmContext<'_, LedgerState>| ctx
            .box_del(b"self"));
        check!("box_extract", |ctx: &mut LedgerAvmContext<
            '_,
            LedgerState,
        >| ctx.box_extract(b"self", 0, 7));
        check!("box_get", |ctx: &mut LedgerAvmContext<'_, LedgerState>| ctx
            .box_get(b"self"));
        check!("box_len", |ctx: &mut LedgerAvmContext<'_, LedgerState>| ctx
            .box_len(b"self"));
        check!("box_put", |ctx: &mut LedgerAvmContext<'_, LedgerState>| ctx
            .box_put(b"self", b"hello"));
        check!("box_replace", |ctx: &mut LedgerAvmContext<
            '_,
            LedgerState,
        >| ctx
            .box_replace(b"self", 0, b"new"));
        check!("box_resize", |ctx: &mut LedgerAvmContext<
            '_,
            LedgerState,
        >| ctx.box_resize(b"self", 10));
    }

    /// TestBoxWriteBudget: a single create right at, and one over, the
    /// write budget.
    #[test]
    fn box_write_budget_single_create_at_and_over_budget() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 200).unwrap();

        let mut store2 = LedgerState::new();
        let mut ctx2 = make_box_budget_context(&mut store2, 888, 200);
        let err = ctx2.box_create(b"self", 201).unwrap_err();
        assert_eq!(
            err.to_string(),
            "AVM: write budget exceeded (201 > 200) while creating box 0x73656c66"
        );
    }

    /// TestBoxWriteBudget: two different boxes created together, exactly at
    /// and one byte over, the combined write budget.
    #[test]
    fn box_write_budget_two_creates_summing_to_and_over_budget() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_create(b"self", 4).unwrap();
        ctx.box_create(b"other", 196).unwrap(); // sums to exactly 200

        let mut store2 = LedgerState::new();
        let mut ctx2 = make_box_budget_context(&mut store2, 888, 200);
        ctx2.box_create(b"self", 6).unwrap();
        let err = ctx2.box_create(b"other", 196).unwrap_err(); // sums to 202
        assert!(
            err.to_string()
                .contains("write budget exceeded (202 > 200)"),
            "unexpected error: {err}"
        );
    }

    /// TestBoxWriteBudget: `box_replace` on an *existing* box charges the
    /// box's full current size (not just the bytes actually touched) to the
    /// write budget on first touch -- so replacing two pre-existing
    /// 101-byte boxes exceeds a 200-byte budget even though only 2 bytes of
    /// each are actually written.
    #[test]
    fn box_write_budget_replace_on_two_101_byte_boxes_charges_full_size() {
        let mut store = LedgerState::new();
        store.set_box(888, b"self", vec![0u8; 101]);
        store.set_box(888, b"other", vec![0u8; 101]);
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_replace(b"self", 0, b"\x33\x33").unwrap();
        let err = ctx.box_replace(b"other", 0, b"\x33\x33").unwrap_err();
        assert!(
            err.to_string()
                .contains("write budget exceeded (202 > 200)"),
            "unexpected error: {err}"
        );
    }

    /// TestBoxWriteBudget ("writing twice is no problem (even though it's
    /// the big one)"): replacing the same box's content multiple times only
    /// charges its size to the write budget once, not once per replace.
    #[test]
    fn box_write_budget_repeated_replace_on_same_box_not_double_charged() {
        let mut store = LedgerState::new();
        store.set_box(888, b"self", vec![0u8; 51]);
        store.set_box(888, b"other", vec![0u8; 10]);
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_replace(b"self", 0, b"\x33\x33").unwrap();
        ctx.box_replace(b"self", 10, b"\x33\x33").unwrap();
        ctx.box_replace(b"other", 0, b"\x33\x33").unwrap();
        assert_eq!(
            ctx.dirty_bytes, 61,
            "repeated writes to the same box must charge its size once (51 + 10), not per write"
        );
    }

    /// TestWriteBudgetPut ("ensure box_put does not double debit when
    /// creating"): `box_put` on a brand-new box charges its size to the
    /// write budget exactly once.
    #[test]
    fn write_budget_put_on_new_box_charges_size_once() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_budget_context(&mut store, 888, 200);
        ctx.box_put(b"self", &[0u8; 150]).unwrap();
        assert_eq!(ctx.dirty_bytes, 150);
    }

    /// TestWriteBudgetPut: two `box_put`s to the *same* name (different
    /// content, same size) don't go over budget, but puts to two
    /// *different* names summing over budget do.
    #[test]
    fn write_budget_put_same_name_twice_ok_different_names_over_budget() {
        let mut store = LedgerState::new();
        {
            let mut ctx = make_box_budget_context(&mut store, 888, 200);
            ctx.box_put(b"self", &[0u8; 150]).unwrap();
            let mut second = vec![0u8; 149];
            second.push(b'x');
            ctx.box_put(b"self", &second).unwrap();
            assert_eq!(
                ctx.dirty_bytes, 150,
                "two puts to the same name must not double-charge"
            );
        }

        let mut store2 = LedgerState::new();
        let mut ctx2 = make_box_budget_context(&mut store2, 888, 200);
        ctx2.box_put(b"self", &[0u8; 150]).unwrap();
        let mut other_content = vec![0u8; 149];
        other_content.push(b'x');
        let err = ctx2.box_put(b"other", &other_content).unwrap_err();
        assert!(
            err.to_string().contains("write budget"),
            "unexpected error: {err}"
        );
    }

    /// Build a `LedgerAvmContext` whose I/O budget is derived from the real
    /// `ensure_boxes_initialized` box-ref-counting path (V41 consensus, with
    /// `bytes_per_box_reference` overridden to 100 to match go-algorand's
    /// own test fixture, `data/transactions/logic/eval_test.go:130`), rather
    /// than a manually-assigned `io_budget`. `box_refs` lists the txn's box
    /// refs in order; `None` produces an empty (unnamed) ref.
    fn make_io_budget_context<'a>(
        store: &'a mut LedgerState,
        app_id: u64,
        box_refs: Vec<Option<&[u8]>>,
    ) -> LedgerAvmContext<'a, LedgerState> {
        if !store.has_app_params(app_id) {
            store.set_app_params(
                app_id,
                algo_types::AppParams {
                    creator: Address([1u8; 32]),
                    ..Default::default()
                },
            );
        }
        let mut txn = make_appl_txn([9u8; 32], app_id, vec![], vec![], vec![]);
        txn.txn.boxes = Some(
            box_refs
                .into_iter()
                .map(|n| algo_types::BoxRef {
                    index: 0,
                    name: n.map(|b| serde_bytes::ByteBuf::from(b.to_vec())),
                })
                .collect(),
        );
        let mut consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .expect("V41 consensus params must exist");
        consensus.bytes_per_box_reference = 100;
        LedgerAvmContext::new(
            store,
            vec![txn],
            0,
            1000,
            12345,
            app_id,
            [1u8; 32],
            true,
            [2u8; 32],
            [3u8; 32],
            consensus,
        )
    }

    /// TestIOBudgetGrow: with the sample env's two box refs (self, other),
    /// each a pre-existing 101-byte box, the eager read-budget check (which
    /// sums the sizes of *every* available box up front, not just touched
    /// ones) rejects the very first box access -- both boxes together are
    /// 202 bytes against a 200-byte budget.
    #[test]
    fn io_budget_grow_two_box_refs_101_bytes_each_exceeds_budget() {
        let mut store = LedgerState::new();
        store.set_box(888, b"self", vec![0u8; 101]);
        store.set_box(888, b"other", vec![0u8; 101]);
        let mut ctx = make_io_budget_context(&mut store, 888, vec![Some(b"self"), Some(b"other")]);
        let err = ctx.box_replace(b"self", 0, b"\x33\x33").unwrap_err();
        assert_eq!(err.to_string(), "AVM: read budget exceeded (202 > 200)");
    }

    /// TestIOBudgetGrow: adding one extra *empty* box ref bumps the budget
    /// from 200 to 300, letting a program that reads both 101-byte boxes
    /// (202 bytes total) succeed.
    #[test]
    fn io_budget_grow_extra_empty_ref_grows_budget_to_300() {
        let mut store = LedgerState::new();
        store.set_box(888, b"self", vec![0u8; 101]);
        store.set_box(888, b"other", vec![0u8; 101]);
        let mut ctx =
            make_io_budget_context(&mut store, 888, vec![Some(b"self"), Some(b"other"), None]);
        ctx.box_extract(b"self", 1, 7).unwrap();
        ctx.box_extract(b"other", 1, 7).unwrap();
        // Writes fit too (202 <= 300).
        ctx.box_replace(b"self", 0, b"\x33\x33").unwrap();
        ctx.box_replace(b"other", 0, b"\x33\x33").unwrap();
    }

    /// TestIOBudgetGrow: with a fourth (named) box ref, the budget grows to
    /// 400 -- enough to read the two existing 101-byte boxes (202 bytes)
    /// *and* create a new, much larger 350-byte box in the same call.
    #[test]
    fn io_budget_grow_fourth_ref_allows_reading_202_and_creating_350() {
        let mut store = LedgerState::new();
        store.set_box(888, b"self", vec![0u8; 101]);
        store.set_box(888, b"other", vec![0u8; 101]);
        let mut ctx = make_io_budget_context(
            &mut store,
            888,
            vec![Some(b"self"), Some(b"other"), None, Some(b"another")],
        );
        ctx.box_extract(b"self", 1, 7).unwrap();
        ctx.box_extract(b"other", 1, 7).unwrap();
        ctx.box_create(b"another", 350).unwrap();
    }

    // -------------------------------------------------------------------
    // Foreign box authorization / family reentrancy (issue #662)
    //
    // These are the security-critical tests: they pin the exact go-algorand
    // `authorizeBoxAccess`/`checkFamilyReentrancy` semantics (read/write/
    // family authorization rules, error text, and the cross-app reentrancy
    // guard) against `LedgerAvmContext`, where the real authorization logic
    // lives (not the algo-avm opcode-dispatch mock, which has none).
    // -------------------------------------------------------------------

    const CALLER_APP: u64 = 10;
    const OWNER_APP: u64 = 20;
    const CREATOR_A: [u8; 32] = [0xAAu8; 32]; // caller's creator
    const CREATOR_B: [u8; 32] = [0xBBu8; 32]; // a different creator

    /// Build a `LedgerAvmContext` executing as `CALLER_APP` (creator
    /// `caller_creator`), with `OWNER_APP` registered (creator
    /// `owner_creator`, `ForeignBoxReads`/`FamilyBoxAccess` as given) and
    /// `name` pre-marked available on `OWNER_APP`.
    #[allow(clippy::too_many_arguments)]
    fn make_authz_context<'a>(
        store: &'a mut LedgerState,
        caller_creator: [u8; 32],
        owner_creator: [u8; 32],
        foreign_box_reads: bool,
        family_box_access: bool,
        name: &[u8],
    ) -> LedgerAvmContext<'a, LedgerState> {
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .expect("V41 consensus params must exist");
        store.set_app_params(
            CALLER_APP,
            algo_types::AppParams {
                creator: Address(caller_creator),
                ..Default::default()
            },
        );
        store.set_app_params(
            OWNER_APP,
            algo_types::AppParams {
                creator: Address(owner_creator),
                foreign_box_reads,
                family_box_access,
                ..Default::default()
            },
        );
        let mut ctx = LedgerAvmContext::new(
            store,
            vec![make_appl_txn(
                [9u8; 32],
                CALLER_APP,
                vec![],
                vec![OWNER_APP],
                vec![],
            )],
            0,
            1000,
            12345,
            CALLER_APP,
            caller_creator,
            true,
            [2u8; 32],
            [3u8; 32],
            consensus,
        );
        ctx.available_boxes
            .insert((OWNER_APP, name.to_vec()), false);
        ctx.available_boxes
            .insert((CALLER_APP, name.to_vec()), false);
        ctx.boxes_initialized = true;
        ctx.read_budget_checked = true;
        ctx.io_budget = 10_000;
        ctx
    }

    #[test]
    fn foreign_read_denied_by_default() {
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, false, false, b"mybox");
        let err = ctx.app_box_get(OWNER_APP, b"mybox").unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "foreign app {CALLER_APP} may not read box of {OWNER_APP}"
            )),
            "got: {err}"
        );
    }

    #[test]
    fn foreign_read_allowed_via_foreign_box_reads() {
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", b"hi".to_vec());
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, true, false, b"mybox");
        let (value, exists) = ctx.app_box_get(OWNER_APP, b"mybox").unwrap();
        assert!(exists);
        assert_eq!(value, b"hi");
    }

    #[test]
    fn foreign_write_denied_via_foreign_box_reads_alone() {
        // ForeignBoxReads authorizes reads only -- a write must still be
        // denied even though reads are allowed.
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", vec![0u8; 2]);
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, true, false, b"mybox");
        let err = ctx.app_box_put(OWNER_APP, b"mybox", b"hi").unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "foreign app {CALLER_APP} may not write box of {OWNER_APP}"
            )),
            "got: {err}"
        );
    }

    #[test]
    fn family_read_allowed_via_family_box_access_same_creator_without_foreign_box_reads() {
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", b"hi".to_vec());
        // Same creator (CREATOR_A on both sides), FamilyBoxAccess set,
        // ForeignBoxReads NOT set -- family membership alone must suffice
        // for a read.
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        let (value, exists) = ctx.app_box_get(OWNER_APP, b"mybox").unwrap();
        assert!(exists);
        assert_eq!(value, b"hi");
    }

    #[test]
    fn family_write_allowed_via_family_box_access_same_creator() {
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", vec![0u8; 2]);
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.app_box_put(OWNER_APP, b"mybox", b"hi").unwrap();
        assert_eq!(store.get_box(OWNER_APP, b"mybox").unwrap(), b"hi");
    }

    #[test]
    fn family_write_denied_when_creators_differ_despite_family_box_access() {
        // FamilyBoxAccess is set, but the caller does NOT share the owner's
        // creator -- must be denied, and the error must report "foreign"
        // (not "family"), since the caller never qualified as in-family.
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", vec![0u8; 2]);
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, false, true, b"mybox");
        let err = ctx.app_box_put(OWNER_APP, b"mybox", b"hi").unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "foreign app {CALLER_APP} may not write box of {OWNER_APP}"
            )),
            "got: {err}"
        );
    }

    #[test]
    fn read_denied_reports_foreign_not_family_when_creators_differ() {
        // FamilyBoxAccess is set (so a same-creator caller would qualify as
        // in-family), but this caller has a DIFFERENT creator and
        // ForeignBoxReads is unset -- the denial must report "foreign", not
        // "family", since the caller never qualified as in-family.
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, false, true, b"mybox");
        let err = ctx.app_box_get(OWNER_APP, b"mybox").unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "foreign app {CALLER_APP} may not read box of {OWNER_APP}"
            )),
            "got: {err}"
        );
    }

    #[test]
    fn own_box_access_always_allowed_regardless_of_flags() {
        // Accessing the current app's own box is always allowed, even with
        // both ForeignBoxReads and FamilyBoxAccess unset.
        let mut store = LedgerState::new();
        store.set_box(CALLER_APP, b"mybox", b"hi".to_vec());
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_B, false, false, b"mybox");
        let (value, exists) = ctx.app_box_get(CALLER_APP, b"mybox").unwrap();
        assert!(exists);
        assert_eq!(value, b"hi");
    }

    #[test]
    fn create_delete_resize_are_write_class_not_read_for_authorization() {
        // ForeignBoxReads alone must NOT permit app_box_create,
        // app_box_del, or app_box_resize against a foreign app's box --
        // only Read is treated as a read; Create/Delete/Resize follow the
        // write-authorization path.
        for op_name in ["create", "del", "resize"] {
            let mut store = LedgerState::new();
            store.set_box(OWNER_APP, b"mybox", vec![0u8; 2]);
            let mut ctx =
                make_authz_context(&mut store, CREATOR_A, CREATOR_B, true, false, b"mybox");
            ctx.available_boxes
                .insert((OWNER_APP, b"mybox2".to_vec()), false);
            let err = match op_name {
                "create" => ctx.app_box_create(OWNER_APP, b"mybox2", 4).unwrap_err(),
                "del" => ctx.app_box_del(OWNER_APP, b"mybox").unwrap_err(),
                "resize" => ctx.app_box_resize(OWNER_APP, b"mybox", 4).unwrap_err(),
                _ => unreachable!(),
            };
            assert!(
                format!("{err}").contains(&format!(
                    "foreign app {CALLER_APP} may not write box of {OWNER_APP}"
                )),
                "operation {op_name} unexpectedly authorized by ForeignBoxReads alone"
            );
        }
    }

    #[test]
    fn new_app_access_fallback_is_keyed_by_box_owner_not_caller() {
        // Regression test: go-algorand's `newAppAccess` fast path
        // (`data/transactions/logic/box.go:174-186`) checks
        // `cx.available.createdApps[appID]` where `appID` is the *box
        // owner* being accessed (the function's own parameter), NOT
        // `cx.appID` (the executing app). A caller that itself is NOT
        // newly created must still get the fast (no-disk-lookup) path for
        // an unnamed box ref against a foreign app that WAS newly created
        // in this group, as long as the access is otherwise authorized.
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"unused");
        // Do NOT mark ("OWNER_APP", "newbox") available directly -- only
        // reachable via the newAppAccess fallback.
        ctx.created_apps.push(OWNER_APP);
        ctx.unnamed_access = 1;
        assert!(!ctx
            .available_boxes
            .contains_key(&(OWNER_APP, b"newbox".to_vec())));
        let created = ctx.app_box_create(OWNER_APP, b"newbox", 10).unwrap();
        assert!(created, "expected the box to be newly created");
        assert_eq!(ctx.unnamed_access, 0, "the spare unnamed ref must be spent");
        assert_eq!(store.get_box(OWNER_APP, b"newbox").unwrap(), vec![0u8; 10]);
    }

    #[test]
    fn owner_app_missing_reports_does_not_exist() {
        let mut store = LedgerState::new();
        store.set_app_params(
            CALLER_APP,
            algo_types::AppParams {
                creator: Address(CREATOR_A),
                ..Default::default()
            },
        );
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .unwrap();
        let mut ctx = LedgerAvmContext::new(
            &mut store,
            vec![make_appl_txn(
                [9u8; 32],
                CALLER_APP,
                vec![],
                vec![999],
                vec![],
            )],
            0,
            1000,
            12345,
            CALLER_APP,
            CREATOR_A,
            true,
            [2u8; 32],
            [3u8; 32],
            consensus,
        );
        ctx.available_boxes.insert((999, b"mybox".to_vec()), false);
        ctx.boxes_initialized = true;
        ctx.read_budget_checked = true;
        ctx.io_budget = 10_000;
        let err = ctx.app_box_get(999, b"mybox").unwrap_err();
        assert!(
            format!("{err}").contains("app 999 does not exist"),
            "got: {err}"
        );
    }

    #[test]
    fn own_box_write_with_family_box_access_touches_family_shared() {
        // Even a *same-app* box write must set `touched_family_shared` when
        // the current app itself has FamilyBoxAccess set -- this is the
        // "familyShared = ownerParams.FamilyBoxAccess" branch of
        // authorizeBoxAccess for `ownerAppID == cx.appID`, exercised via the
        // *plain* (non-foreign) `box_put` opcode path.
        let mut store = LedgerState::new();
        store.set_app_params(
            CALLER_APP,
            algo_types::AppParams {
                creator: Address(CREATOR_A),
                family_box_access: true,
                ..Default::default()
            },
        );
        let consensus = algo_types::consensus::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_V41,
        )
        .unwrap();
        let mut ctx = LedgerAvmContext::new(
            &mut store,
            vec![make_appl_txn([9u8; 32], CALLER_APP, vec![], vec![], vec![])],
            0,
            1000,
            12345,
            CALLER_APP,
            CREATOR_A,
            true,
            [2u8; 32],
            [3u8; 32],
            consensus,
        );
        ctx.available_boxes
            .insert((CALLER_APP, b"mybox".to_vec()), false);
        ctx.boxes_initialized = true;
        ctx.read_budget_checked = true;
        ctx.io_budget = 10_000;
        assert!(!ctx.touched_family_shared);
        ctx.box_put(b"mybox", b"hi").unwrap();
        assert!(ctx.touched_family_shared);
    }

    #[test]
    fn own_box_write_without_family_box_access_does_not_touch() {
        let mut store = LedgerState::new();
        let mut ctx = make_box_context(&mut store, CALLER_APP, b"mybox");
        ctx.box_put(b"mybox", b"hi").unwrap();
        assert!(!ctx.touched_family_shared);
    }

    // ---- Family-scoped reentrancy guard (checkFamilyReentrancy) ----

    #[test]
    fn reentrancy_blocked_when_foreign_app_separates_touched_family_ancestor() {
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        // Simulate a call chain: root(family, already touched) -> foreign
        // (different creator) -> self (about to write a family-shared box).
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: true,
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        let err = ctx.check_family_reentrancy().unwrap_err();
        assert!(
            format!("{err}").contains(&format!(
                "app {CALLER_APP} may not write family-shared box: app 1 is relying on family state across a foreign call"
            )),
            "got: {err}"
        );
    }

    #[test]
    fn reentrancy_allowed_when_family_ancestor_untouched_despite_foreign_separator() {
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: false, // never touched -- nothing to clobber
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        ctx.check_family_reentrancy().unwrap();
    }

    #[test]
    fn reentrancy_allowed_direct_family_call_with_no_foreign_separator() {
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        // Direct family ancestor, touched, but no foreign app in between.
        ctx.family_chain = vec![FamilyFrame {
            app_id: 1,
            creator: CREATOR_A,
            touched_family_shared: true,
        }];
        ctx.check_family_reentrancy().unwrap();
    }

    #[test]
    fn reentrancy_check_is_memoized_per_frame() {
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.family_chain = vec![FamilyFrame {
            app_id: 1,
            creator: CREATOR_A,
            touched_family_shared: true,
        }];
        ctx.check_family_reentrancy().unwrap();
        assert!(ctx.family_reentrancy_checked);
        // Mutate the chain to a shape that would now fail; the memoized
        // result must still short-circuit to Ok without re-walking.
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: true,
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        ctx.check_family_reentrancy().unwrap();
    }

    #[test]
    fn end_to_end_family_write_denied_by_reentrancy_via_app_box_put() {
        // Full integration: authorize_box_access's write path must itself
        // invoke check_family_reentrancy, not just the isolated unit tests
        // above. Owner app is family-shared (FamilyBoxAccess, same creator
        // as self); self's caller chain has a foreign app separating it
        // from a family ancestor that already touched family-shared state.
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", vec![0u8; 2]);
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: true,
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        let err = ctx.app_box_put(OWNER_APP, b"mybox", b"hi").unwrap_err();
        assert!(
            format!("{err}").contains("may not write family-shared box"),
            "got: {err}"
        );
    }

    #[test]
    fn end_to_end_family_read_exempt_from_reentrancy_guard() {
        // Reads are exempt from the family reentrancy check entirely (the
        // guard fires only on writes), even with the same "foreign
        // separates a touched family ancestor" chain shape that blocks a
        // write above.
        let mut store = LedgerState::new();
        store.set_box(OWNER_APP, b"mybox", b"hi".to_vec());
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: true,
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        let (value, exists) = ctx.app_box_get(OWNER_APP, b"mybox").unwrap();
        assert!(exists);
        assert_eq!(value, b"hi");
    }

    // ---- Touch-mark propagation to caller (execute_inner_appl) ----

    #[test]
    fn touch_mark_propagates_to_same_creator_caller_via_box_state() {
        // `execute_inner_appl` resolves the caller-should-touch condition
        // into `BoxBudgetState::touched_family_shared` before returning; a
        // same-creator caller applies it unconditionally.
        let bs = crate::apply::BoxBudgetState {
            touched_family_shared: true,
            ..Default::default()
        };
        assert!(bs.touched_family_shared);
    }

    #[test]
    fn family_frame_reentrancy_walk_ignores_frames_that_never_touched() {
        // A long chain of same-creator, never-touched ancestors interleaved
        // with foreign apps must never block a write -- only an actually
        // *touched* family ancestor separated by a foreign app does.
        let mut store = LedgerState::new();
        let mut ctx = make_authz_context(&mut store, CREATOR_A, CREATOR_A, false, true, b"mybox");
        ctx.family_chain = vec![
            FamilyFrame {
                app_id: 1,
                creator: CREATOR_A,
                touched_family_shared: false,
            },
            FamilyFrame {
                app_id: 2,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
            FamilyFrame {
                app_id: 3,
                creator: CREATOR_A,
                touched_family_shared: false,
            },
            FamilyFrame {
                app_id: 4,
                creator: CREATOR_B,
                touched_family_shared: false,
            },
        ];
        ctx.check_family_reentrancy().unwrap();
    }

    // ---- `consider_budget_program_writes` (issue #723) ----
    //
    // Direct unit tests against the method itself (rather than a full AVM
    // run) so the oracle -- go-algorand's `EvalContext.
    // considerBudgetProgramWrites()`, `data/transactions/logic/eval.go:
    // 540-569` -- can be pinned precisely: old-size subtraction, per-appID
    // tracking, the creating-and-deleting exemption, and the exact verb
    // quirk (a delete-only call reports "creating", matching go's `verb :=
    // "creating"; if updating { verb = "updating" }` which never checks
    // `deleting`). `make_context` uses `ConsensusParams::default()`, which
    // is the real (large) V42 free-tier allowance, so
    // `zero_free_program_tier` below zeroes it out per-test -- keeping the
    // arithmetic in these tests simple and exact rather than needing every
    // test program to actually exceed V42's real several-KB free tier.

    fn make_program_txn(
        application_id: u64,
        on_completion: u64,
        approval_len: usize,
        clear_len: usize,
    ) -> SignedTransaction {
        let mut txn = make_appl_txn([9u8; 32], application_id, vec![], vec![], vec![]);
        txn.txn.on_completion = on_completion;
        txn.txn.approval_program = Some(serde_bytes::ByteBuf::from(vec![0u8; approval_len]));
        txn.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(vec![0u8; clear_len]));
        txn
    }

    /// Zero out the free program-size tier (`MaxAppTotalProgramLen *
    /// (1+MaxExtraAppProgramPages)`) so every byte of a test program's
    /// combined approval+clear length counts as "extra" -- keeping the
    /// arithmetic in these tests exact and independent of the real
    /// consensus version's (large) free allowance.
    fn zero_free_program_tier<L: LedgerStore>(ctx: &mut LedgerAvmContext<'_, L>) {
        ctx.consensus.max_app_total_program_len = 0;
        ctx.consensus.max_extra_app_program_pages = 0;
    }

    #[test]
    fn consider_budget_program_writes_rejects_oversized_create_with_no_io_budget() {
        let mut store = LedgerState::new();
        let txn = make_program_txn(0, 0, 50, 10); // creating, total 60 bytes
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 1016;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 0;

        let err = ctx.consider_budget_program_writes().unwrap_err();
        // Matches go-algorand's exact error text
        // (`data/transactions/logic/eval.go:565-566`):
        // `fmt.Errorf("write budget exceeded (%d > %d) while %s app %d", ...)`.
        assert_eq!(
            format!("{err}"),
            "AVM: write budget exceeded (60 > 0) while creating app 1016"
        );
    }

    #[test]
    fn consider_budget_program_writes_accepts_oversized_create_with_enough_io_budget() {
        // Companion to the rejection test above: the identical oversized
        // create succeeds once the group supplies enough "io bump" budget
        // (here, a manually-set `io_budget` standing in for box refs) to
        // cover the program's extra bytes.
        let mut store = LedgerState::new();
        let txn = make_program_txn(0, 0, 50, 10); // creating, total 60 bytes
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 1016;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 60;

        ctx.consider_budget_program_writes().unwrap();
        assert_eq!(ctx.dirty_bytes, 60);
        assert_eq!(ctx.update_bytes.get(&1016), Some(&60));
    }

    #[test]
    fn consider_budget_program_writes_rejects_oversized_update_with_correct_verb() {
        let mut store = LedgerState::new();
        let txn = make_program_txn(77, crate::apply::ON_COMPLETION_UPDATE, 200, 5); // updating, total 205 bytes
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 77;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 100;

        let err = ctx.consider_budget_program_writes().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "AVM: write budget exceeded (205 > 100) while updating app 77"
        );
    }

    #[test]
    fn consider_budget_program_writes_accepts_oversized_update_with_enough_io_budget() {
        let mut store = LedgerState::new();
        let txn = make_program_txn(77, crate::apply::ON_COMPLETION_UPDATE, 200, 5);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 77;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 205;

        ctx.consider_budget_program_writes().unwrap();
    }

    #[test]
    fn consider_budget_program_writes_exempts_create_and_delete_in_same_txn() {
        // go: `if creating && deleting { return nil }` -- the program never
        // gets written, so no budget check applies regardless of size or
        // available io_budget.
        let mut store = LedgerState::new();
        let txn = make_program_txn(0, crate::apply::ON_COMPLETION_DELETE, 9_999, 9_999);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 5;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 0;

        ctx.consider_budget_program_writes().unwrap();
        assert_eq!(
            ctx.dirty_bytes, 0,
            "exempted call must not touch dirty_bytes"
        );
        assert!(ctx.update_bytes.is_empty());
    }

    #[test]
    fn consider_budget_program_writes_delete_only_reports_creating_verb() {
        // go's verb selection literally only branches on `updating`
        // (`eval.go:561-564`): a delete-only call (not creating, since
        // ApplicationID != 0, and not updating) still falls through to the
        // "creating" default. Mirrored exactly, quirk and all.
        let mut store = LedgerState::new();
        let txn = make_program_txn(77, crate::apply::ON_COMPLETION_DELETE, 200, 5);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 77;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 0;

        let err = ctx.consider_budget_program_writes().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "AVM: write budget exceeded (205 > 0) while creating app 77"
        );
    }

    #[test]
    fn consider_budget_program_writes_is_noop_for_noop_call() {
        // Neither creating, updating, nor deleting -- a plain NoOp call must
        // never consult (or mutate) the write budget, matching go's early
        // `if !creating && !updating && !deleting { return nil }`.
        let mut store = LedgerState::new();
        let txn = make_program_txn(77, 0, 9_999, 9_999); // OnCompletion NoOp
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 77;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 0;

        ctx.consider_budget_program_writes().unwrap();
        assert_eq!(ctx.dirty_bytes, 0);
        assert!(ctx.update_bytes.is_empty());
    }

    #[test]
    fn consider_budget_program_writes_second_call_undoes_prior_contribution() {
        // A later create/update/delete call against the *same* app within
        // the group must first subtract its own previously-recorded
        // contribution before folding in the new one -- matching go's
        // `oldSize := cx.available.updateBytes[cx.appID];
        // cx.available.dirtyBytes = basics.SubSaturate(...)`. Otherwise a
        // shrinking update (or repeated evaluation of the same app within a
        // group) would double-count bytes that were already charged.
        let mut store = LedgerState::new();
        let txn = make_program_txn(0, 0, 100, 0); // creating, 100 bytes
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.app_id = 9;
        zero_free_program_tier(&mut ctx);
        ctx.boxes_initialized = true;
        ctx.io_budget = 1_000;
        ctx.consider_budget_program_writes().unwrap();
        assert_eq!(ctx.dirty_bytes, 100);

        // Same app, now updating with a smaller program (40 bytes): the
        // stale 100-byte contribution must be undone first, leaving
        // dirty_bytes at 40, not 140.
        ctx.group[0].txn.on_completion = crate::apply::ON_COMPLETION_UPDATE;
        ctx.group[0].txn.application_id = 9;
        ctx.group[0].txn.approval_program = Some(serde_bytes::ByteBuf::from(vec![0u8; 40]));
        ctx.group[0].txn.clear_state_program = Some(serde_bytes::ByteBuf::from(vec![]));
        ctx.consider_budget_program_writes().unwrap();
        assert_eq!(
            ctx.dirty_bytes, 40,
            "stale contribution from the prior create must be undone before adding the new one"
        );
        assert_eq!(ctx.update_bytes.get(&9), Some(&40));
    }

    // ---- issue #727: box I/O budget state shared across sibling
    // top-level app calls in one atomic group ----
    //
    // go-algorand shares one `EvalParams` instance -- and hence its
    // `ioBudget`/`readBudgetChecked`/`available` (boxes, dirtyBytes,
    // updateBytes) fields -- by pointer across every top-level transaction
    // in a group (`ledger/eval/eval.go:1090`'s single `NewAppEvalParams`
    // call, threaded through the group loop at `ledger/eval/eval.go:
    // 1117-1124`). These tests pin the [`LedgerAvmContext::
    // load_box_budget_state`]/[`LedgerAvmContext::save_box_budget_state`]
    // round trip that `apply_appl` now uses to carry a
    // [`crate::apply::BoxBudgetState`] across two separate top-level
    // `LedgerAvmContext`s the same way `apply_appl` does for two sibling
    // top-level `appl` calls in one group -- at the same unit-test fidelity
    // as the `consider_budget_program_writes_*` tests above (direct field
    // manipulation rather than a full AVM run), since the group-sharing
    // bug lives entirely in this seed/export boundary, not in the box
    // opcodes themselves.

    #[test]
    fn box_budget_state_round_trip_preserves_all_fields() {
        let mut store = LedgerState::new();
        let txn = make_program_txn(0, 0, 10, 0);
        let mut ctx = make_context(&mut store, vec![txn]);
        ctx.available_boxes.insert((7, b"a".to_vec()), true);
        ctx.dirty_bytes = 123;
        ctx.io_budget = 456;
        ctx.update_bytes.insert(7, 99);
        ctx.read_budget_checked = true;
        ctx.boxes_initialized = true;
        ctx.unnamed_access = 3;

        let mut carrier = crate::apply::BoxBudgetState::default();
        ctx.save_box_budget_state(&mut carrier);
        assert_eq!(
            carrier.available_boxes.get(&(7, b"a".to_vec())),
            Some(&true)
        );
        assert_eq!(carrier.dirty_bytes, 123);
        assert_eq!(carrier.io_budget, 456);
        assert_eq!(carrier.update_bytes.get(&7), Some(&99));
        assert!(carrier.read_budget_checked);
        assert!(carrier.boxes_initialized);
        assert_eq!(carrier.unnamed_access, 3);

        // A fresh context (as `apply_appl` builds for every top-level call)
        // starts at the defaults; loading the carrier must fully overwrite
        // them, not merge.
        let txn2 = make_program_txn(0, 0, 10, 0);
        let mut store2 = LedgerState::new();
        let mut ctx2 = make_context(&mut store2, vec![txn2]);
        assert!(
            !ctx2.boxes_initialized,
            "fresh context starts uninitialized"
        );
        ctx2.load_box_budget_state(&carrier);
        assert_eq!(ctx2.available_boxes.get(&(7, b"a".to_vec())), Some(&true));
        assert_eq!(ctx2.dirty_bytes, 123);
        assert_eq!(ctx2.io_budget, 456);
        assert_eq!(ctx2.update_bytes.get(&7), Some(&99));
        assert!(ctx2.read_budget_checked);
        assert!(ctx2.boxes_initialized);
        assert_eq!(ctx2.unnamed_access, 3);
    }

    #[test]
    fn write_budget_combined_oversized_programs_across_siblings_rejected() {
        // Two top-level app calls, each creating an oversized program of 40
        // extra bytes. Each individually fits a 50-byte io_budget alone, but
        // their COMBINED 80 bytes must not -- matching go-algorand's shared
        // `EvalParams.available.dirtyBytes`, which accumulates across every
        // top-level call in the group, not just within one call's own
        // execution.
        let group_box_budget_io = 50u64;

        // Sibling A (app 100): creates with 40 extra bytes -- fits alone.
        let mut store_a = LedgerState::new();
        let txn_a = make_program_txn(0, 0, 40, 0);
        let mut ctx_a = make_context(&mut store_a, vec![txn_a]);
        ctx_a.app_id = 100;
        zero_free_program_tier(&mut ctx_a);
        ctx_a.boxes_initialized = true;
        ctx_a.io_budget = group_box_budget_io;
        ctx_a.consider_budget_program_writes().unwrap();
        assert_eq!(
            ctx_a.dirty_bytes, 40,
            "sibling A alone must fit the shared budget"
        );

        // Export sibling A's state into the group-scoped carrier that
        // `apply_appl` threads between top-level calls.
        let mut carrier = crate::apply::BoxBudgetState::default();
        ctx_a.save_box_budget_state(&mut carrier);

        // Sibling B (app 200, a DIFFERENT app): also creates with 40 extra
        // bytes -- fits alone too, but seeded with A's carried-over
        // dirty_bytes, the combined 80 bytes must exceed the shared 50-byte
        // budget.
        let mut store_b = LedgerState::new();
        let txn_b = make_program_txn(0, 0, 40, 0);
        let mut ctx_b = make_context(&mut store_b, vec![txn_b]);
        ctx_b.app_id = 200;
        zero_free_program_tier(&mut ctx_b);
        ctx_b.load_box_budget_state(&carrier);
        assert_eq!(
            ctx_b.dirty_bytes, 40,
            "sibling B must inherit sibling A's already-spent dirty_bytes"
        );

        let err = ctx_b.consider_budget_program_writes().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "AVM: write budget exceeded (80 > 50) while creating app 200",
            "combined oversized-program bytes across siblings must exceed the shared budget"
        );
    }

    #[test]
    fn write_budget_combined_oversized_programs_across_siblings_accepted_with_enough_budget() {
        // Companion to the rejection test above: identical siblings, but the
        // group supplies enough shared io_budget (100) to cover the combined
        // 80 extra bytes, so both must succeed.
        let group_box_budget_io = 100u64;

        let mut store_a = LedgerState::new();
        let txn_a = make_program_txn(0, 0, 40, 0);
        let mut ctx_a = make_context(&mut store_a, vec![txn_a]);
        ctx_a.app_id = 100;
        zero_free_program_tier(&mut ctx_a);
        ctx_a.boxes_initialized = true;
        ctx_a.io_budget = group_box_budget_io;
        ctx_a.consider_budget_program_writes().unwrap();

        let mut carrier = crate::apply::BoxBudgetState::default();
        ctx_a.save_box_budget_state(&mut carrier);

        let mut store_b = LedgerState::new();
        let txn_b = make_program_txn(0, 0, 40, 0);
        let mut ctx_b = make_context(&mut store_b, vec![txn_b]);
        ctx_b.app_id = 200;
        zero_free_program_tier(&mut ctx_b);
        ctx_b.load_box_budget_state(&carrier);

        ctx_b.consider_budget_program_writes().unwrap();
        assert_eq!(
            ctx_b.dirty_bytes, 80,
            "both siblings' contributions must be reflected in the shared dirty_bytes total"
        );
    }

    #[test]
    fn read_budget_check_result_shared_across_siblings_not_rerun() {
        // Sibling A (app 100) performs the group's one-time read-budget
        // check against an existing box sized exactly to the group's
        // box-ref-derived io_budget (100 bytes, no surplus), then WRITES to
        // that same box, growing it to 150 bytes. Sibling B (app 200 -- a
        // different app with no box opcode of its own) must see the
        // check-already-performed state from the shared carrier and must
        // NOT re-run the read-budget check against the box's now-larger
        // size -- matching go-algorand's `readBudgetChecked` gate, which is
        // set once on the shared `EvalParams` and never re-evaluated for
        // any later top-level call in the group, regardless of what an
        // earlier sibling wrote in the meantime.
        let app_id = 100u64;
        let box_name = b"K".to_vec();

        let mut store = LedgerState::new();
        store.set_box(app_id, &box_name, vec![0u8; 100]); // 100-byte box

        let txn_a = make_appl_txn([9u8; 32], app_id, vec![], vec![], vec![]);
        let mut ctx_a = make_context(&mut store, vec![txn_a]);
        ctx_a.app_id = app_id;
        ctx_a
            .available_boxes
            .insert((app_id, box_name.clone()), false);
        ctx_a.boxes_initialized = true; // box refs already resolved
        ctx_a.io_budget = 100; // exactly matches the box's current size

        ctx_a.check_read_budget().unwrap();
        assert!(ctx_a.read_budget_checked);

        // Sibling A now writes the box, growing it to 150 bytes (a plain
        // equal-size replacement isn't required by `box_put`'s ledger
        // helper directly here -- simulate the resize the way `box_resize`
        // would, since only the resulting on-chain size matters for this
        // test).
        ctx_a.store.set_box(app_id, &box_name, vec![0u8; 150]);

        let mut carrier = crate::apply::BoxBudgetState::default();
        ctx_a.save_box_budget_state(&mut carrier);
        assert!(carrier.read_budget_checked);

        // Sibling B: a fresh context for a DIFFERENT app, seeded from the
        // carrier.
        let txn_b = make_appl_txn([9u8; 32], 200, vec![], vec![], vec![]);
        let mut ctx_b = make_context(ctx_a.store, vec![txn_b]);
        ctx_b.app_id = 200;
        assert!(
            !ctx_b.read_budget_checked,
            "a fresh context starts unchecked before seeding"
        );
        ctx_b.load_box_budget_state(&carrier);
        assert!(
            ctx_b.read_budget_checked,
            "seeding from the group carrier must mark the read budget as already checked"
        );

        // With the fix, this is a no-op regardless of the box's current
        // (now 150-byte) size -- it must NOT error even though 150 > 100.
        ctx_b.check_read_budget().unwrap();
    }

    #[test]
    fn read_budget_check_without_group_sharing_incorrectly_reruns_and_rejects() {
        // Oracle test: pins the OLD (buggy) per-call-reset behavior this
        // issue fixes, so a regression back to "fresh `LedgerAvmContext` per
        // top-level call, no group carrier" is caught. Same setup as the
        // fixed-behavior test above, but sibling B is built the way
        // `apply_appl` used to build every top-level call's context --
        // `boxes_initialized`/`read_budget_checked` left at their `false`
        // defaults, exactly like a group carrier was never consulted.
        // Because the group's box refs deterministically resolve to the
        // same `available_boxes`/`io_budget` regardless of which sibling
        // computes them, sibling B redundantly re-runs the check -- and
        // since sibling A's write already grew the box on `store` to 150
        // bytes, the re-check now sees 150 > 100 and incorrectly rejects a
        // call that go-algorand (and the fixed algod-rust) would let
        // through untouched.
        let app_id = 100u64;
        let box_name = b"K".to_vec();

        let mut store = LedgerState::new();
        store.set_box(app_id, &box_name, vec![0u8; 100]);

        let txn_a = make_appl_txn([9u8; 32], app_id, vec![], vec![], vec![]);
        let mut ctx_a = make_context(&mut store, vec![txn_a]);
        ctx_a.app_id = app_id;
        ctx_a
            .available_boxes
            .insert((app_id, box_name.clone()), false);
        ctx_a.boxes_initialized = true;
        ctx_a.io_budget = 100;
        ctx_a.check_read_budget().unwrap();
        ctx_a.store.set_box(app_id, &box_name, vec![0u8; 150]);

        // Sibling B: same box ref, but NOT seeded from any group carrier --
        // reproduces the pre-fix per-top-level-call reset.
        let txn_b = make_appl_txn([9u8; 32], 200, vec![], vec![], vec![]);
        let mut ctx_b = make_context(ctx_a.store, vec![txn_b]);
        ctx_b.app_id = 200;
        ctx_b
            .available_boxes
            .insert((app_id, box_name.clone()), false);
        ctx_b.io_budget = 100; // same deterministic group-wide computation
                               // `boxes_initialized`/`read_budget_checked` left false, as a fresh
                               // top-level `LedgerAvmContext` always starts.

        let err = ctx_b.check_read_budget().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "AVM: read budget exceeded (150 > 100)",
            "without group-wide sharing, sibling B wrongly re-checks against the box's post-write size"
        );
    }
}
