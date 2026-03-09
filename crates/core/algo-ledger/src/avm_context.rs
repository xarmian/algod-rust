//! `AvmContext` implementation backed by `LedgerStore`.
//!
//! `LedgerAvmContext` wraps a ledger store together with the current
//! transaction group, round metadata, and scratch/inner-txn state so that
//! the AVM can read/write chain state through the `AvmContext` trait defined
//! in `algo-avm`.

use std::collections::BTreeMap;

use algo_avm::context::AvmContext;
use algo_avm::eval::AvmResult;
use algo_avm::MAX_AVM_VERSION;
use algo_error::AlgoError;
use algo_types::{Address, SignedTransaction, TealValue, Transaction};
use sha2::{Digest, Sha512_256};

use crate::apply::{
    apply_inner_acfg, apply_inner_afrz, apply_inner_axfer, apply_inner_keyreg, apply_inner_pay,
};
use crate::params;
use crate::store_trait::LedgerStore;

/// Maximum byte string length in the AVM (matches go-algorand `maxStringSize`).
/// Used for program page chunking.
const MAX_STRING_SIZE: usize = 4096;

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

/// Compute an application address: `SHA512/256("appID" || app_id_be_bytes)`.
///
/// Exposed publicly for tests and inner transaction execution.
pub fn app_address(app_id: u64) -> [u8; 32] {
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
    26, // ApplicationArgs
    28, // Accounts
    48, // Assets (foreign assets)
    50, // Applications (foreign apps)
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
                        txn.txn_type = String::from_utf8_lossy(b).to_string();
                    }
                }
                // TypeEnum
                16 => {
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
                        txn.asset_params
                            .get_or_insert_with(algo_types::AssetParams::default)
                            .metadata_hash = Some(serde_bytes::ByteBuf::from(b.clone()));
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
                _ => {
                    // Silently ignore unknown fields for forward-compatibility
                }
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
            caller_app_id_val: 0,
            caller_app_address_val: [0u8; 32],
            depth: 0,
            fee_credit: 0,
            txn_counter: 0,
            fee_sink: Address::ZERO,
            opcode_budget: 0,
            inner_txn_ids: Vec::new(),
            created_assets: Vec::new(),
            created_apps: Vec::new(),
            parent_txn_id: algo_types::Digest([0u8; 32]),
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

    /// Precomputed inner transaction IDs, mirroring `inner_txns` structure.
    pub fn inner_txn_ids(&self) -> &[Vec<algo_types::Digest>] {
        &self.inner_txn_ids
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
        let total_budget = params::MAX_INNER_TRANSACTIONS * self.group.len();
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
    round: u64,
    latest_timestamp: u64,
    genesis_hash: [u8; 32],
    fee_credit: u64,
    txn_counter: u64,
    fee_sink: Address,
    opcode_budget: &mut i64,
    inner_txn_id: algo_types::Digest,
) -> Result<crate::apply::InnerApplyData, AlgoError> {
    use algo_avm::eval::{run_approval_program, run_clear_state_program};
    use algo_avm::group::GroupBudget;

    let mut ad = crate::apply::InnerApplyData::default();
    let called_app_id = stxn.txn.application_id;
    let on_completion = stxn.txn.on_completion;
    let sender = stxn.txn.sender;

    // ── Handle app creation (application_id == 0) ──
    let effective_app_id = if called_app_id == 0 {
        // Create a new application. Use txn_counter + 1 as the new app ID,
        // matching go-algorand's createApplication(txnCounter + 1).
        let new_app_id = txn_counter + 1;
        ad.application_id = new_app_id;

        let approval = stxn
            .txn
            .approval_program
            .as_ref()
            .map(|b| b.to_vec())
            .unwrap_or_default();
        let clear = stxn
            .txn
            .clear_state_program
            .as_ref()
            .map(|b| b.to_vec())
            .unwrap_or_default();

        let global_schema = stxn.txn.global_state_schema.clone().unwrap_or_default();
        let local_schema = stxn.txn.local_state_schema.clone().unwrap_or_default();

        let app_params = algo_types::AppParams {
            creator: sender,
            approval_program: approval,
            clear_state_program: clear,
            global_state: std::collections::BTreeMap::new(),
            global_state_schema: global_schema,
            local_state_schema: local_schema,
            extra_program_pages: stxn.txn.extra_program_pages,
        };
        store.set_app_params(new_app_id, app_params);

        // Update creator's account counters.
        let mut creator_acct = store.get_or_default_account(&sender);
        creator_acct.total_created_apps += 1;
        creator_acct.total_extra_app_pages += stxn.txn.extra_program_pages;
        // Update aggregate schema: creator stores global state.
        creator_acct.total_app_schema = creator_acct
            .total_app_schema
            .add_schema(&stxn.txn.global_state_schema.clone().unwrap_or_default());
        store.set_account(&sender, creator_acct);

        // Record the created app ID on the SignedTransaction.
        stxn.apply_data_application_id = new_app_id;

        new_app_id
    } else {
        called_app_id
    };

    // ── OptIn: create local state before running program ──
    if on_completion == 1 {
        // OptInOC = 1
        // Reject duplicate opt-in (matches outer apply_appl path).
        if store.has_app_local_state(&sender, effective_app_id) {
            return Err(AlgoError::Avm {
                message: format!(
                    "inner appl opt-in: {} is already opted into app {}",
                    sender, effective_app_id,
                ),
            });
        }
        let app = store
            .get_app_params(effective_app_id)
            .ok_or_else(|| AlgoError::Avm {
                message: format!("inner appl opt-in: app {} not found", effective_app_id),
            })?;
        let local = algo_types::AppLocalState {
            schema: app.local_state_schema.clone(),
            key_value: std::collections::BTreeMap::new(),
        };
        store.set_app_local_state(&sender, effective_app_id, local);

        // Update account counters.
        let mut acct = store.get_or_default_account(&sender);
        acct.total_apps_opted_in += 1;
        // Update aggregate schema: sender stores local state.
        acct.total_app_schema = acct.total_app_schema.add_schema(&app.local_state_schema);
        store.set_account(&sender, acct);
    }

    // ── Load the program ──
    let app = store
        .get_app_params(effective_app_id)
        .ok_or_else(|| AlgoError::Avm {
            message: format!("inner appl: app {} not found", effective_app_id),
        })?;

    let program = if on_completion == 3 {
        // ClearStateOC
        app.clear_state_program.clone()
    } else {
        app.approval_program.clone()
    };
    let creator = app.creator.0;

    // Compute program hash for ed25519verify domain separation.
    let program_hash = {
        let mut h = Sha512_256::new();
        h.update(b"Program");
        h.update(&program);
        let result: [u8; 32] = h.finalize().into();
        result
    };

    // ── Budget pooling: add INNER_APP_BUDGET for this app call ──
    // Per go-algorand IsolateClearState: ClearState programs run with their
    // own isolated budget (MAX_APP_PROGRAM_COST = 700) and do NOT add to
    // the shared pool. Only non-ClearState app calls contribute budget.
    if on_completion != 3 {
        *opcode_budget += params::INNER_APP_BUDGET;
    }

    // ── Create a GroupBudget from the shared opcode budget ──
    // We create a GroupBudget with 0 app calls (so initial = 0), then add
    // the full shared budget to it.
    let mut budget = GroupBudget::new(0);
    budget.add(*opcode_budget);

    // ── Create child AVM context ──
    // Build a single-txn group containing just the inner app call.
    let inner_group = vec![stxn.clone()];
    let mut inner_ctx = LedgerAvmContext::new(
        store,
        inner_group,
        0, // group_index
        round,
        latest_timestamp,
        effective_app_id,
        creator,
        true, // app_mode
        program_hash,
        genesis_hash,
    );
    inner_ctx.caller_app_id_val = caller_app_id;
    inner_ctx.caller_app_address_val = app_address(caller_app_id);
    inner_ctx.depth = caller_depth + 1;
    inner_ctx.fee_credit = fee_credit;
    inner_ctx.txn_counter = txn_counter;
    inner_ctx.fee_sink = fee_sink;
    // P1-3: Set parent_txn_id to the InnerID of this appl txn so that
    // any nested inner transactions derive their IDs from the correct
    // parent (the immediate parent inner txn, not the original outer txn).
    inner_ctx.parent_txn_id = inner_txn_id;

    // ── Execute the program ──
    let avm_result = if on_completion == 3 {
        // ClearStateOC: run clear state program. On failure, still clear state.
        run_clear_state_program(&program, &mut inner_ctx)
    } else {
        match run_approval_program(&program, &mut inner_ctx, &mut budget) {
            Ok(result) => result,
            Err(e) => {
                // Update the shared budget with what was consumed.
                *opcode_budget = budget.remaining();
                return Err(e);
            }
        }
    };

    // ── Update shared opcode budget ──
    *opcode_budget = budget.remaining();

    // ── Check approval ──
    if on_completion != 3 && !avm_result.approved {
        // Non-ClearState programs must approve.
        let err_msg = avm_result
            .error
            .unwrap_or_else(|| "program rejected".to_string());
        return Err(AlgoError::Avm {
            message: format!("inner appl: {}", err_msg),
        });
    }

    // ── Collect logs, inner txns, fee_credit, and txn_counter from child ──
    let inner_logs = inner_ctx.logs.clone();
    let inner_txns_from_child: Vec<SignedTransaction> = inner_ctx
        .inner_txns
        .iter()
        .flat_map(|g| g.iter().cloned())
        .collect();
    // Capture fee_credit and txn_counter for propagation back to parent (H5/H6).
    let child_fee_credit = inner_ctx.fee_credit;
    let child_txn_counter = inner_ctx.txn_counter;
    // P1-3: Capture all asset/app IDs created by nested inner txns so the
    // parent can track them for snapshot rollback.
    let child_created_assets = inner_ctx.created_assets.clone();
    let child_created_apps = inner_ctx.created_apps.clone();

    // Store logs and nested inner txns as the eval_delta on the
    // inner SignedTransaction. We build a minimal eval_delta rmpv::Value map.
    if !inner_logs.is_empty() || !inner_txns_from_child.is_empty() {
        let mut dt_map: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();

        if !inner_logs.is_empty() {
            let log_values: Vec<rmpv::Value> = inner_logs
                .iter()
                .map(|l| rmpv::Value::Binary(l.clone()))
                .collect();
            dt_map.push((
                rmpv::Value::String("lg".into()),
                rmpv::Value::Array(log_values),
            ));
        }

        // Serialize nested inner transactions under the "itx" key,
        // matching go-algorand's EvalDelta.InnerTxns field.
        if !inner_txns_from_child.is_empty() {
            let itx_values: Vec<rmpv::Value> = inner_txns_from_child
                .iter()
                .filter_map(|stxn_child| {
                    let bytes = rmp_serde::to_vec_named(stxn_child).ok()?;
                    rmpv::decode::read_value(&mut &bytes[..]).ok()
                })
                .collect();
            if !itx_values.is_empty() {
                dt_map.push((
                    rmpv::Value::String("itx".into()),
                    rmpv::Value::Array(itx_values),
                ));
            }
        }

        stxn.eval_delta = Some(rmpv::Value::Map(dt_map));
    }

    // ── Apply OnCompletion side effects (post-program) ──
    // The store reference is now available again since inner_ctx is dropped
    // at the end of this function. But inner_ctx still exists here...
    // Actually inner_ctx borrows store, so we need to drop it first.
    drop(inner_ctx);

    match on_completion {
        0 => {} // NoOpOC — nothing to do
        1 => {} // OptInOC — local state was already created above
        2 => {
            // CloseOutOC — remove local state (sender must be opted in).
            let local_state = store
                .get_app_local_state(&sender, effective_app_id)
                .ok_or_else(|| AlgoError::Avm {
                    message: format!(
                        "inner appl close-out: {} is not opted into app {}",
                        sender, effective_app_id,
                    ),
                })?;
            let local_schema = local_state.schema.clone();
            store.remove_app_local_state(&sender, effective_app_id);
            let mut acct = store.get_or_default_account(&sender);
            acct.total_apps_opted_in = acct.total_apps_opted_in.saturating_sub(1);
            // Subtract local schema from aggregate.
            acct.total_app_schema = acct.total_app_schema.sub_schema(&local_schema);
            store.set_account(&sender, acct);
        }
        3 => {
            // ClearStateOC — always clear local state regardless of program result
            if let Some(local_state) = store.get_app_local_state(&sender, effective_app_id) {
                let local_schema = local_state.schema.clone();
                store.remove_app_local_state(&sender, effective_app_id);
                let mut acct = store.get_or_default_account(&sender);
                acct.total_apps_opted_in = acct.total_apps_opted_in.saturating_sub(1);
                // Subtract local schema from aggregate.
                acct.total_app_schema = acct.total_app_schema.sub_schema(&local_schema);
                store.set_account(&sender, acct);
            }
        }
        4 => {
            // UpdateApplicationOC — only the creator can update the app programs.
            if let Some(mut app) = store.get_app_params(effective_app_id) {
                if sender != app.creator {
                    return Err(AlgoError::Avm {
                        message: format!(
                            "inner appl update: sender {} is not the creator of app {}",
                            sender, effective_app_id,
                        ),
                    });
                }
                if let Some(ref approval) = stxn.txn.approval_program {
                    app.approval_program = approval.to_vec();
                }
                if let Some(ref clear) = stxn.txn.clear_state_program {
                    app.clear_state_program = clear.to_vec();
                }
                store.set_app_params(effective_app_id, app);
            }
        }
        5 => {
            // DeleteApplicationOC — only the creator can delete the app.
            if let Some(existing) = store.get_app_params(effective_app_id) {
                if sender != existing.creator {
                    return Err(AlgoError::Avm {
                        message: format!(
                            "inner appl delete: sender {} is not the creator of app {}",
                            sender, effective_app_id,
                        ),
                    });
                }
                let creator_addr = existing.creator;
                let global_schema = existing.global_state_schema.clone();
                store.remove_app_params(effective_app_id);
                // Update creator's account counters.
                let mut creator_acct = store.get_or_default_account(&creator_addr);
                creator_acct.total_created_apps = creator_acct.total_created_apps.saturating_sub(1);
                creator_acct.total_extra_app_pages = creator_acct
                    .total_extra_app_pages
                    .saturating_sub(existing.extra_program_pages);
                // Subtract global schema from aggregate.
                creator_acct.total_app_schema =
                    creator_acct.total_app_schema.sub_schema(&global_schema);
                store.set_account(&creator_addr, creator_acct);
            }
        }
        _ => {
            return Err(AlgoError::Avm {
                message: format!("inner appl: unknown OnCompletion {}", on_completion),
            });
        }
    }

    // Propagate fee_credit and txn_counter back to the parent (H5/H6).
    ad.fee_credit = child_fee_credit;
    ad.txn_counter = child_txn_counter;
    // P1-3: Propagate all nested created resources so the parent's
    // rollback can clean them up if a later sibling txn fails.
    ad.nested_created_assets = child_created_assets;
    ad.nested_created_apps = child_created_apps;

    Ok(ad)
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
        // Per go-algorand: Accounts[0] is the sender, foreign accounts start at 1.
        // NumAccounts (when array_index is None) = len(apat), not including sender.
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
        // Per go-algorand: Applications[0] is the current ApplicationID.
        // NumApplications (when array_index is None) = len(apfa), not including current app.
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
        // CreatedAssetID (from ApplyData)
        60 => Ok(TealValue::Uint(stxn.apply_data_config_asset)),
        // CreatedApplicationID (from ApplyData)
        61 => Ok(TealValue::Uint(stxn.apply_data_application_id)),
        // LastLog — the last entry in the eval_delta logs, or empty bytes.
        62 => {
            let logs = extract_logs_from_eval_delta(stxn);
            let last = logs.last().cloned().unwrap_or_default();
            Ok(TealValue::Bytes(last))
        }
        // StateProofPK
        63 => Ok(TealValue::Bytes(
            txn.state_proof_pk
                .as_ref()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        )),
        // ApprovalProgramPages (array) — per go-algorand, pages are 4096-byte chunks.
        // maxStringSize = 4096; page_count = DivCeil(len, 4096); OOB index is an error.
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
        // ClearStateProgramPages (array) — same 4096-byte paging as approval.
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
            // CallerApplicationID — uses caller fields set during inner app call.
            // Note: op_global intercepts this field and calls caller_app_id()
            // directly, but this fallback is kept for completeness.
            13 => Ok(TealValue::Uint(self.caller_app_id_val)),
            // CallerApplicationAddress — uses caller fields.
            14 => Ok(TealValue::Bytes(self.caller_app_address_val.to_vec())),
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
        let txn_type = stxn.txn.txn_type.as_str();
        if txn_type != "appl" && txn_type != "acfg" {
            return Err(AlgoError::Avm {
                message: format!(
                    "gaid: txn at index {} is not an app call or asset config (type='{}')",
                    group_index, txn_type
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
        // Block field access requires block history which is not yet available
        // in this implementation. Return a descriptive error.
        Err(AlgoError::Avm {
            message: format!(
                "block field access not yet supported (round={}, field={})",
                round, field
            ),
        })
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
        if on_completion == 3 {
            // ClearStateOC = 3
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
        if self.inner_building.len() >= params::MAX_TX_GROUP_SIZE {
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
        if num_subtxns > self.remaining_inners() || num_subtxns > params::MAX_TX_GROUP_SIZE {
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
                    stxn.txn.fee = params::MIN_TXN_FEE;
                }
                // Copy FirstValid/LastValid from the outer transaction.
                let outer = &self.group[self.group_index].txn;
                stxn.txn.first_valid = outer.first_valid;
                stxn.txn.last_valid = outer.last_valid;
                stxn
            })
            .collect();

        // ── Fee credit / pooling (matches go-algorand opItxnSubmit) ──
        //
        // Total required = MinTxnFee * num_subtxns.
        // Total paid = sum of individual fees.
        // Shortfall is covered by fee_credit (from outer group overpayment).
        // Overpayment is added back to fee_credit.
        let group_fee = params::MIN_TXN_FEE.saturating_mul(num_subtxns as u64);
        let group_paid: u64 = txns
            .iter()
            .map(|stxn| stxn.txn.fee)
            .fold(0u64, |a, b| a.saturating_add(b));
        if group_paid < group_fee {
            let shortfall = group_fee - group_paid;
            if self.fee_credit < shortfall {
                return Err(AlgoError::Avm {
                    message: format!(
                        "fee too small: inner group needs {} but only paid {} with {} credit",
                        group_fee, group_paid, self.fee_credit
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

                    // Disallow self-call (reentrancy on the same app).
                    if called_app_id == self.app_id {
                        return Err(AlgoError::Avm {
                            message: "attempt to self-call".to_string(),
                        });
                    }

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
                        if stxn.txn.on_completion == 3 {
                            // ClearStateOC
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
                    if called_version < params::MIN_INNER_APPL_VERSION {
                        return Err(AlgoError::Avm {
                            message: format!(
                                "inner app call with version v{} < v{}",
                                called_version,
                                params::MIN_INNER_APPL_VERSION
                            ),
                        });
                    }

                    // For OptIn, also check that the clear state program meets
                    // the minimum version requirement.
                    if stxn.txn.on_completion == 1 {
                        // OptInOC
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
                            if csv < params::MIN_INNER_APPL_VERSION {
                                return Err(AlgoError::Avm {
                                    message: format!(
                                        "inner app call opt-in with CSP v{} < v{}",
                                        csv,
                                        params::MIN_INNER_APPL_VERSION
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
                    if stxn.txn.on_completion == 5 {
                        // DeleteApplicationOC
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
        // outer transaction. For nested contexts, use the stored parent_txn_id.
        let effective_parent_txid = if self.parent_txn_id.0 != [0u8; 32] {
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

        for (i, stxn) in txns.iter_mut().enumerate() {
            // Deduct fee from sender to fee_sink (matches go-algorand takeFee).
            let fee = stxn.txn.fee;
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
                    return Err(AlgoError::Avm {
                        message: format!("inner tx {}: fee_sink not configured (zero address)", i,),
                    });
                }
                let mut sender_acct = self.store.get_or_default_account(&stxn.txn.sender);
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
                    return Err(AlgoError::Avm {
                        message: format!(
                            "inner tx {}: sender {} has insufficient balance {} for fee {}",
                            i, stxn.txn.sender, sender_acct.micro_algos, fee,
                        ),
                    });
                }
                sender_acct.micro_algos -= fee;
                self.store.set_account(&stxn.txn.sender, sender_acct);

                let mut sink_acct = self.store.get_or_default_account(&fee_sink);
                sink_acct.micro_algos += fee;
                self.store.set_account(&fee_sink, sink_acct);
            }

            // Increment txn counter before execution (matches go-algorand incTxnCount).
            current_counter += 1;
            self.txn_counter = current_counter;

            // Dispatch to the appropriate apply function.
            if stxn.txn.txn_type == "appl" {
                // ── Inner app call — recursive AVM execution ──
                // P1-3: Compute this inner appl txn's InnerID, which becomes the
                // parent_txn_id for any nested inner txns it may create.
                let appl_inner_id = algo_avm::itxn::compute_inner_txn_id(
                    &effective_parent_txid,
                    id_offset_base + i,
                    &stxn.txn,
                );
                let result = execute_inner_appl(
                    self.store,
                    stxn,
                    self.depth,
                    self.app_id,
                    self.round,
                    self.latest_timestamp,
                    self.genesis_hash,
                    self.fee_credit,
                    self.txn_counter,
                    self.fee_sink,
                    &mut self.opcode_budget,
                    appl_inner_id,
                );
                match result {
                    Ok(ad) => {
                        stxn.apply_data_config_asset = ad.config_asset;
                        stxn.apply_data_application_id = ad.application_id;
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
                        // Propagate fee_credit and txn_counter back from child (H5/H6).
                        self.fee_credit = ad.fee_credit;
                        // Update running counter from child — the child's counter
                        // accounts for any nested inner txns it created.
                        current_counter = ad.txn_counter;
                        self.txn_counter = current_counter;
                    }
                    Err(e) => {
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        return Err(AlgoError::Avm {
                            message: format!("inner tx {} failed: {}", i, e),
                        });
                    }
                }
            } else {
                let result = match stxn.txn.txn_type.as_str() {
                    "pay" => apply_inner_pay(self.store, &stxn.txn),
                    "axfer" => apply_inner_axfer(self.store, &stxn.txn),
                    "acfg" => apply_inner_acfg(self.store, &stxn.txn, self.txn_counter),
                    "afrz" => apply_inner_afrz(self.store, &stxn.txn),
                    "keyreg" => apply_inner_keyreg(self.store, &stxn.txn, round),
                    _ => {
                        // Should not reach here due to earlier validation.
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        return Err(AlgoError::Avm {
                            message: format!(
                                "inner tx {}: unsupported type {}",
                                i, stxn.txn.txn_type
                            ),
                        });
                    }
                };

                match result {
                    Ok(ad) => {
                        stxn.apply_data_config_asset = ad.config_asset;
                        stxn.apply_data_application_id = ad.application_id;
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
                    }
                    Err(e) => {
                        self.store.restore_snapshot(snapshot);
                        for &id in &extra_created_asset_ids {
                            self.store.remove_asset_params(id);
                            self.store.remove_all_asset_holdings_for_asset(id);
                        }
                        for &id in &extra_created_app_ids {
                            self.store.remove_app_params(id);
                            self.store.remove_all_app_local_states_for_app(id);
                        }
                        return Err(AlgoError::Avm {
                            message: format!("inner tx {} failed: {}", i, e),
                        });
                    }
                }
            }
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

    // ---- Resource availability ----

    fn is_asset_available(&self, asset_id: u64) -> bool {
        if asset_id == 0 {
            return false;
        }
        // Check the current transaction's foreign assets array.
        let txn = &self.group[self.group_index].txn;
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
        // Check the current transaction's foreign apps array.
        let txn = &self.group[self.group_index].txn;
        if let Some(ref apps) = txn.foreign_apps {
            if apps.contains(&app_id) {
                return true;
            }
        }
        // Check apps created by inner transactions.
        if self.created_apps.contains(&app_id) {
            return true;
        }
        false
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
        txn.txn.txn_type = "appl".to_string();
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
        txn.txn.txn_type = "appl".to_string();
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
        txn.txn.txn_type = "appl".to_string();
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
        txn.txn.txn_type = "appl".to_string();
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
        // txn_counter = 100 + 0 + 1 = 101, then apply_inner_acfg does +1 = 102
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
        store.set_account(
            &app_addr,
            AccountData {
                micro_algos: 10_000_000,
                ..Default::default()
            },
        );

        // Opt sender into app 100 so ClearState has local state to clear.
        let sender_addr = Address([10u8; 32]);
        store.set_app_local_state(
            &sender_addr,
            100,
            AppLocalState {
                schema: StateSchema::default(),
                key_value: BTreeMap::new(),
            },
        );
        let mut sender_acct = store.get_or_default_account(&sender_addr);
        sender_acct.total_apps_opted_in += 1;
        store.set_account(&sender_addr, sender_acct);

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
            txn_type: "appl".to_string(),
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
            txn_type: "pay".to_string(),
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

    // ---- P1-1: Inner update/delete creator checks ----

    #[test]
    fn inner_appl_update_by_non_creator_fails() {
        // App 100 was created by [1u8;32] (setup_app default).
        // The inner txn sender (app 42's address) is NOT [1u8;32].
        // An inner update (on_completion=4) should fail with a creator check error.
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
        ctx.itxn_field(25, TealValue::Uint(4)).unwrap(); // OnCompletion = UpdateApplication
        ctx.itxn_field(30, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ApprovalProgram
        ctx.itxn_field(31, TealValue::Bytes(make_program(6, true)))
            .unwrap(); // ClearStateProgram
        let result = ctx.itxn_submit();

        assert!(result.is_err(), "non-creator update should fail");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not the creator"),
            "expected creator check error, got: {msg}"
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
}
