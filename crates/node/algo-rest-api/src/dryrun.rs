//! Dryrun execution engine.
//!
//! Implements the `/v2/teal/dryrun` endpoint logic, matching go-algorand's
//! `dryrunRequest` / `doDryrunRequest` from `daemon/algod/api/server/v2/dryrun.go`.

use std::collections::HashMap;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use algo_avm::{
    assemble_string, disassemble, parse, run_approval_program_with_tracer,
    run_logicsig_program_with_tracer, AvmContext, AvmValue, EvalTracer, GroupBudget, Program,
    ProgramType,
};
use algo_error::AlgoError;
use algo_ledger::avm_context::app_address;
use algo_types::{
    consensus::{consensus_params_for_version, ConsensusParams, CONSENSUS_CURRENT_VERSION},
    Address, SignedTransaction, TealValue,
};

use crate::models::{
    AccountResponse, AccountStateDelta, ApiApplication, ApiEvalDelta, DryrunRequest,
    DryrunResponse, DryrunSource, DryrunState, DryrunTealValue, DryrunTxnResult, EvalDeltaKeyValue,
    StateDelta,
};

// ---------------------------------------------------------------------------
// On-completion constants (matching go-algorand transactions.OnCompletion)
// ---------------------------------------------------------------------------

const ON_COMPLETION_OPT_IN: u64 = 1;
const ON_COMPLETION_CLEAR_STATE: u64 = 3;

// ---------------------------------------------------------------------------
// Helper: AvmValue / TealValue → DryrunTealValue
// ---------------------------------------------------------------------------

fn avm_value_to_dryrun(v: &AvmValue) -> DryrunTealValue {
    match v {
        AvmValue::Uint64(n) => DryrunTealValue {
            value_type: 2,
            uint: *n,
            bytes: String::new(),
        },
        AvmValue::Bytes(b) => DryrunTealValue {
            value_type: 1,
            uint: 0,
            bytes: BASE64.encode(b),
        },
    }
}

// ---------------------------------------------------------------------------
// DryrunDebugReceiver — EvalTracer that captures per-step state
// ---------------------------------------------------------------------------

/// Captures per-step AVM state for dryrun trace output.
///
/// Holds a clone of the parsed `Program` to map instruction-index (the `pc`
/// value from `after_opcode`) to byte offset, and also stores the disassembly
/// lines so we can compute the source line number.
#[derive(Default)]
pub struct DryrunDebugReceiver {
    /// The parsed program (used for instruction-index → byte-offset mapping).
    program: Option<Program>,
    /// Disassembly lines (split from `disassemble()` output).
    disassembly: Vec<String>,
    /// Accumulated trace history.
    pub history: Vec<DryrunState>,
    /// Whether this is a LogicSig or app program.
    pub program_type: Option<ProgramType>,
    /// Whether the program passed.
    pub passed: bool,
    /// Error message from execution (if any).
    pub error: Option<String>,
    /// Final scratch space captured from the last `after_opcode` call.
    pub final_scratch: Option<Vec<AvmValue>>,
}

impl DryrunDebugReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize from program bytes. Parses the program and computes
    /// disassembly.
    pub fn init_program(&mut self, program_bytes: &[u8]) {
        if let Ok(parsed) = parse(program_bytes) {
            self.program = Some(parsed);
        }
        if let Ok(text) = disassemble(program_bytes) {
            self.disassembly = text.lines().map(|l| l.to_string()).collect();
        }
    }

    /// Get the disassembly lines.
    pub fn disassembly_lines(&self) -> &[String] {
        &self.disassembly
    }

    /// Map an instruction index to a byte offset in the program.
    fn instruction_to_offset(&self, instruction_index: usize) -> usize {
        if let Some(ref prog) = self.program {
            if instruction_index < prog.instructions.len() {
                return prog.instructions[instruction_index].offset;
            }
        }
        0
    }

    /// Map a byte offset to a line number in the disassembly.
    /// Go's dryrun uses the line index from the disassembly, which includes
    /// the `#pragma version N` line at index 0.
    fn offset_to_line(&self, offset: usize) -> usize {
        // The disassembly lines are: "#pragma version N", then one line per
        // instruction. Line 0 is the pragma, line 1 is the first instruction
        // (offset = version_byte_size, typically 2 for version >= 2).
        // We find the instruction index in the program that has this offset
        // and add 1 for the pragma line.
        if let Some(ref prog) = self.program {
            for (i, instr) in prog.instructions.iter().enumerate() {
                if instr.offset == offset {
                    // Line = i + 1 (pragma line is 0)
                    return i + 1;
                }
            }
        }
        0
    }

    /// Trim scratch to only include entries up to the last non-zero value.
    fn trim_scratch(scratch: &[AvmValue]) -> Option<Vec<DryrunTealValue>> {
        // Find last non-zero index
        let last = scratch.iter().rposition(|v| {
            !matches!(v, AvmValue::Uint64(0)) && !matches!(v, AvmValue::Bytes(b) if b.is_empty())
        });
        match last {
            Some(idx) => {
                let trimmed: Vec<DryrunTealValue> =
                    scratch[..=idx].iter().map(avm_value_to_dryrun).collect();
                Some(trimmed)
            }
            None => None,
        }
    }
}

impl EvalTracer for DryrunDebugReceiver {
    fn before_program(&mut self, program_type: ProgramType) {
        self.program_type = Some(program_type);
    }

    fn after_program(&mut self, _program_type: ProgramType, pass: bool, error: Option<&str>) {
        self.passed = pass;
        self.error = error.map(|s| s.to_string());
    }

    fn after_opcode(
        &mut self,
        pc: usize,
        _opcode: u8,
        stack: &[AvmValue],
        scratch: &[AvmValue],
        error: Option<&str>,
    ) {
        let byte_offset = self.instruction_to_offset(pc);
        let line = self.offset_to_line(byte_offset);

        let stack_vals: Vec<DryrunTealValue> = stack.iter().map(avm_value_to_dryrun).collect();
        let scratch_vals = Self::trim_scratch(scratch);

        // Always capture the latest scratch for gload support
        self.final_scratch = Some(scratch.to_vec());

        let state = DryrunState {
            error: error.map(|s| s.to_string()),
            line,
            pc: byte_offset,
            scratch: scratch_vals,
            stack: stack_vals,
        };
        self.history.push(state);
    }
}

// ---------------------------------------------------------------------------
// DryrunAvmContext — in-memory sandbox AvmContext for dryrun
// ---------------------------------------------------------------------------

/// App params tuple: (approval_program, clear_state_program, creator_address).
type AppParamsEntry = (Vec<u8>, Vec<u8>, [u8; 32]);

/// Local state delta map: key → Option<TealValue> (None = delete).
type LocalDeltaMap = HashMap<Vec<u8>, Option<TealValue>>;

/// In-memory AVM context for dryrun execution.
///
/// Provides account balances, app state, asset holdings, etc. from the
/// `DryrunRequest` data, and tracks state writes (deltas).
pub struct DryrunAvmContext {
    /// Transaction group.
    pub group: Vec<SignedTransaction>,
    /// Current transaction index in the group.
    pub group_index: usize,
    /// Current round.
    pub round: u64,
    /// Latest timestamp.
    pub latest_timestamp: i64,
    /// Current app ID.
    pub app_id: u64,
    /// Creator address.
    pub creator: [u8; 32],
    /// Consensus params.
    pub consensus: ConsensusParams,
    /// Genesis hash (empty for dryrun).
    pub genesis_hash: [u8; 32],
    /// Whether we are in app mode.
    pub app_mode: bool,
    /// LogicSig arguments.
    pub lsig_args: Vec<Vec<u8>>,

    // ---- In-memory state from request ----
    /// Account balances: address → microAlgos.
    pub account_balances: HashMap<[u8; 32], u64>,
    /// Account min balances: address → microAlgos.
    pub account_min_balances: HashMap<[u8; 32], u64>,
    /// Account status: address → status string.
    pub account_status: HashMap<[u8; 32], String>,
    /// App global state: app_id → (key → TealValue).
    pub app_global_state: HashMap<u64, HashMap<Vec<u8>, TealValue>>,
    /// App local state: (address, app_id) → (key → TealValue).
    pub app_local_state: HashMap<([u8; 32], u64), HashMap<Vec<u8>, TealValue>>,
    /// App params: app_id → (approval_program, clear_program, creator).
    pub app_params: HashMap<u64, AppParamsEntry>,
    /// Asset holdings: (address, asset_id) → (amount, frozen).
    pub asset_holdings: HashMap<([u8; 32], u64), (u64, bool)>,
    /// Asset params: asset_id → ApiAssetParams (simplified as creator address).
    pub asset_params: HashMap<u64, [u8; 32]>,
    /// Opted-in apps per account: address → set of app_ids.
    pub opted_in_apps: HashMap<[u8; 32], Vec<u64>>,

    // ---- Group scratch space ----
    /// Scratch space from each completed txn in the group, indexed by group_index.
    pub group_scratch: Vec<Vec<AvmValue>>,

    // ---- Delta tracking ----
    /// Global state delta: app_id → (key → Option<TealValue>).
    pub global_deltas: HashMap<u64, HashMap<Vec<u8>, Option<TealValue>>>,
    /// Local state delta: (address, app_id) → (key → Option<TealValue>).
    pub local_deltas: HashMap<([u8; 32], u64), LocalDeltaMap>,
    /// Log messages.
    pub logs: Vec<Vec<u8>>,
}

/// Shared mutable state that persists across transactions in a dryrun group.
///
/// Built once from the `DryrunRequest` data, then swapped in/out of each
/// per-txn `DryrunAvmContext` so that state mutations (e.g. `app_global_put`)
/// are visible to subsequent transactions.
struct DryrunSharedState {
    app_global_state: HashMap<u64, HashMap<Vec<u8>, TealValue>>,
    app_local_state: HashMap<([u8; 32], u64), HashMap<Vec<u8>, TealValue>>,
    app_params: HashMap<u64, AppParamsEntry>,
    account_balances: HashMap<[u8; 32], u64>,
    account_min_balances: HashMap<[u8; 32], u64>,
    account_status: HashMap<[u8; 32], String>,
    asset_holdings: HashMap<([u8; 32], u64), (u64, bool)>,
    asset_params: HashMap<u64, [u8; 32]>,
    opted_in_apps: HashMap<[u8; 32], Vec<u64>>,
    group_scratch: Vec<Vec<AvmValue>>,
}

impl DryrunSharedState {
    /// Build shared state from the request's `accounts` and `apps` arrays.
    fn from_request(
        accounts: &[AccountResponse],
        apps: &[ApiApplication],
        group_size: usize,
    ) -> Self {
        let mut state = Self {
            app_global_state: HashMap::new(),
            app_local_state: HashMap::new(),
            app_params: HashMap::new(),
            account_balances: HashMap::new(),
            account_min_balances: HashMap::new(),
            account_status: HashMap::new(),
            asset_holdings: HashMap::new(),
            asset_params: HashMap::new(),
            opted_in_apps: HashMap::new(),
            group_scratch: vec![Vec::new(); group_size],
        };

        // Load accounts
        for acct in accounts {
            if let Ok(addr) = Address::from_str(&acct.address) {
                state.account_balances.insert(addr.0, acct.amount);
                state.account_min_balances.insert(addr.0, acct.min_balance);
                state.account_status.insert(addr.0, acct.status.clone());

                // Load asset holdings
                if let Some(ref assets) = acct.assets {
                    for holding in assets {
                        state.asset_holdings.insert(
                            (addr.0, holding.asset_id),
                            (holding.amount, holding.is_frozen),
                        );
                    }
                }

                // Load app local states
                if let Some(ref locals) = acct.apps_local_state {
                    for local in locals {
                        let mut kv = HashMap::new();
                        if let Some(ref kvs) = local.key_value {
                            for entry in kvs {
                                let key = BASE64.decode(&entry.key).unwrap_or_default();
                                let val = api_teal_value_to_internal(&entry.value);
                                kv.insert(key, val);
                            }
                        }
                        state.app_local_state.insert((addr.0, local.id), kv);
                        state
                            .opted_in_apps
                            .entry(addr.0)
                            .or_default()
                            .push(local.id);
                    }
                }

                // Load created apps
                if let Some(ref created) = acct.created_apps {
                    for app in created {
                        let mut global_state = HashMap::new();
                        if let Some(ref gs) = app.params.global_state {
                            for entry in gs {
                                let key = BASE64.decode(&entry.key).unwrap_or_default();
                                let val = api_teal_value_to_internal(&entry.value);
                                global_state.insert(key, val);
                            }
                        }
                        state.app_global_state.insert(app.id, global_state);
                        state.app_params.insert(
                            app.id,
                            (
                                app.params.approval_program.clone(),
                                app.params.clear_state_program.clone(),
                                addr.0,
                            ),
                        );
                    }
                }
            }
        }

        // Load apps from the request's apps array
        for app in apps {
            let creator_addr = Address::from_str(&app.params.creator)
                .map(|a| a.0)
                .unwrap_or([0u8; 32]);

            // Only insert if not already loaded from accounts
            state.app_params.entry(app.id).or_insert_with(|| {
                (
                    app.params.approval_program.clone(),
                    app.params.clear_state_program.clone(),
                    creator_addr,
                )
            });

            state.app_global_state.entry(app.id).or_insert_with(|| {
                let mut gs = HashMap::new();
                if let Some(ref kvs) = app.params.global_state {
                    for entry in kvs {
                        let key = BASE64.decode(&entry.key).unwrap_or_default();
                        let val = api_teal_value_to_internal(&entry.value);
                        gs.insert(key, val);
                    }
                }
                gs
            });
        }

        state
    }

    /// Move shared state maps into a `DryrunAvmContext`, leaving empty maps behind.
    fn take_into_ctx(&mut self, ctx: &mut DryrunAvmContext) {
        ctx.app_global_state = std::mem::take(&mut self.app_global_state);
        ctx.app_local_state = std::mem::take(&mut self.app_local_state);
        ctx.app_params = std::mem::take(&mut self.app_params);
        ctx.account_balances = std::mem::take(&mut self.account_balances);
        ctx.account_min_balances = std::mem::take(&mut self.account_min_balances);
        ctx.account_status = std::mem::take(&mut self.account_status);
        ctx.asset_holdings = std::mem::take(&mut self.asset_holdings);
        ctx.asset_params = std::mem::take(&mut self.asset_params);
        ctx.opted_in_apps = std::mem::take(&mut self.opted_in_apps);
        ctx.group_scratch = std::mem::take(&mut self.group_scratch);
    }

    /// Move (possibly mutated) state maps back from the context into shared state.
    fn restore_from_ctx(&mut self, ctx: &mut DryrunAvmContext) {
        self.app_global_state = std::mem::take(&mut ctx.app_global_state);
        self.app_local_state = std::mem::take(&mut ctx.app_local_state);
        self.app_params = std::mem::take(&mut ctx.app_params);
        self.account_balances = std::mem::take(&mut ctx.account_balances);
        self.account_min_balances = std::mem::take(&mut ctx.account_min_balances);
        self.account_status = std::mem::take(&mut ctx.account_status);
        self.asset_holdings = std::mem::take(&mut ctx.asset_holdings);
        self.asset_params = std::mem::take(&mut ctx.asset_params);
        self.opted_in_apps = std::mem::take(&mut ctx.opted_in_apps);
        self.group_scratch = std::mem::take(&mut ctx.group_scratch);
    }
}

impl DryrunAvmContext {
    /// Build a new context for a specific transaction, with empty state maps.
    ///
    /// State maps are populated via `DryrunSharedState::take_into_ctx()`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group: Vec<SignedTransaction>,
        group_index: usize,
        round: u64,
        latest_timestamp: i64,
        app_id: u64,
        creator: [u8; 32],
        consensus: ConsensusParams,
        app_mode: bool,
    ) -> Self {
        Self {
            group,
            group_index,
            round,
            latest_timestamp,
            app_id,
            creator,
            consensus,
            genesis_hash: [0u8; 32],
            app_mode,
            lsig_args: Vec::new(),
            account_balances: HashMap::new(),
            account_min_balances: HashMap::new(),
            account_status: HashMap::new(),
            app_global_state: HashMap::new(),
            app_local_state: HashMap::new(),
            app_params: HashMap::new(),
            asset_holdings: HashMap::new(),
            asset_params: HashMap::new(),
            opted_in_apps: HashMap::new(),
            group_scratch: Vec::new(),
            global_deltas: HashMap::new(),
            local_deltas: HashMap::new(),
            logs: Vec::new(),
        }
    }
}

/// Convert an `ApiTealValue` to an internal `TealValue`.
fn api_teal_value_to_internal(v: &crate::models::ApiTealValue) -> TealValue {
    match v.value_type {
        1 => TealValue::Bytes(BASE64.decode(&v.bytes).unwrap_or_default()),
        _ => TealValue::Uint(v.uint),
    }
}

impl AvmContext for DryrunAvmContext {
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
        algo_avm::read_txn_field(stxn, field, array_index, group_index)
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
            0 => Ok(TealValue::Uint(self.consensus.min_txn_fee)),
            1 => Ok(TealValue::Uint(self.consensus.min_balance)),
            2 => Ok(TealValue::Uint(self.consensus.max_txn_life)),
            3 => Ok(TealValue::Bytes(vec![0u8; 32])),
            4 => Ok(TealValue::Uint(self.group.len() as u64)),
            5 => Ok(TealValue::Uint(self.consensus.logic_sig_version)),
            6 => Ok(TealValue::Uint(self.round)),
            7 => {
                // Go returns 0 for negative timestamps. Treat as unsigned
                // reinterpretation, clamping negatives to 0.
                let ts = if self.latest_timestamp < 0 {
                    0u64
                } else {
                    self.latest_timestamp as u64
                };
                Ok(TealValue::Uint(ts))
            }
            8 => Ok(TealValue::Uint(self.app_id)),
            9 => Ok(TealValue::Bytes(self.creator.to_vec())),
            10 => Ok(TealValue::Bytes(app_address(self.app_id).to_vec())),
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
            12 => Ok(TealValue::Uint(0)), // OpcodeBudget (handled by op_global)
            13 => Ok(TealValue::Uint(0)), // CallerApplicationID
            14 => Ok(TealValue::Bytes(vec![0u8; 32])), // CallerApplicationAddress
            15 => Ok(TealValue::Uint(self.consensus.min_balance)), // AssetCreateMinBalance
            16 => Ok(TealValue::Uint(self.consensus.min_balance)), // AssetOptInMinBalance
            17 => Ok(TealValue::Bytes(self.genesis_hash.to_vec())), // GenesisHash
            18 => Ok(TealValue::Uint(if self.consensus.payouts_enabled {
                1
            } else {
                0
            })),
            19 => Ok(TealValue::Uint(self.consensus.payouts_go_online_fee)),
            20 => Ok(TealValue::Uint(self.consensus.payouts_percent)),
            21 => Ok(TealValue::Uint(self.consensus.payouts_min_balance)),
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
        let txn = &self.group[self.group_index].txn;
        if index == 0 {
            return Ok(txn.sender.0);
        }
        let accounts = txn.accounts.as_deref().unwrap_or(&[]);
        let idx = (index as usize).wrapping_sub(1);
        if idx < accounts.len() {
            Ok(accounts[idx].0)
        } else {
            Err(AlgoError::Avm {
                message: format!("account index {index} out of range"),
            })
        }
    }

    fn resolve_asset(&self, index: u64) -> Result<u64, AlgoError> {
        let txn = &self.group[self.group_index].txn;
        let assets = txn.foreign_assets.as_deref().unwrap_or(&[]);
        if (index as usize) < assets.len() {
            Ok(assets[index as usize])
        } else {
            Err(AlgoError::Avm {
                message: format!("asset index {index} out of range"),
            })
        }
    }

    fn resolve_app(&self, index: u64) -> Result<u64, AlgoError> {
        if index == 0 {
            return Ok(self.app_id);
        }
        let txn = &self.group[self.group_index].txn;
        let apps = txn.foreign_apps.as_deref().unwrap_or(&[]);
        let idx = (index as usize).wrapping_sub(1);
        if idx < apps.len() {
            Ok(apps[idx])
        } else {
            Err(AlgoError::Avm {
                message: format!("app index {index} out of range"),
            })
        }
    }

    // ---- State reads ----

    fn app_opted_in(&self, account: &[u8; 32], app_id: u64) -> Result<bool, AlgoError> {
        Ok(self.app_local_state.contains_key(&(*account, app_id)))
    }

    fn app_local_get(
        &self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<Option<TealValue>, AlgoError> {
        // Check local deltas first
        if let Some(deltas) = self.local_deltas.get(&(*account, app_id)) {
            if let Some(delta_val) = deltas.get(key) {
                return Ok(delta_val.clone());
            }
        }
        // Then check base state
        Ok(self
            .app_local_state
            .get(&(*account, app_id))
            .and_then(|kv| kv.get(key))
            .cloned())
    }

    fn app_global_get(&self, app_id: u64, key: &[u8]) -> Result<Option<TealValue>, AlgoError> {
        // Check global deltas first
        if let Some(deltas) = self.global_deltas.get(&app_id) {
            if let Some(delta_val) = deltas.get(key) {
                return Ok(delta_val.clone());
            }
        }
        // Then check base state
        Ok(self
            .app_global_state
            .get(&app_id)
            .and_then(|kv| kv.get(key))
            .cloned())
    }

    // ---- State writes ----

    fn app_local_put(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        // Track delta
        self.local_deltas
            .entry((*account, app_id))
            .or_default()
            .insert(key.to_vec(), Some(value.clone()));
        // Update in-memory state
        self.app_local_state
            .entry((*account, app_id))
            .or_default()
            .insert(key.to_vec(), value);
        Ok(())
    }

    fn app_local_del(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<(), AlgoError> {
        // Track delta
        self.local_deltas
            .entry((*account, app_id))
            .or_default()
            .insert(key.to_vec(), None);
        // Update in-memory state
        if let Some(kv) = self.app_local_state.get_mut(&(*account, app_id)) {
            kv.remove(key);
        }
        Ok(())
    }

    fn app_global_put(
        &mut self,
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        // Track delta
        self.global_deltas
            .entry(app_id)
            .or_default()
            .insert(key.to_vec(), Some(value.clone()));
        // Update in-memory state
        self.app_global_state
            .entry(app_id)
            .or_default()
            .insert(key.to_vec(), value);
        Ok(())
    }

    fn app_global_del(&mut self, app_id: u64, key: &[u8]) -> Result<(), AlgoError> {
        // Track delta
        self.global_deltas
            .entry(app_id)
            .or_default()
            .insert(key.to_vec(), None);
        // Update in-memory state
        if let Some(kv) = self.app_global_state.get_mut(&app_id) {
            kv.remove(key);
        }
        Ok(())
    }

    // ---- Account / asset / app parameter queries ----

    fn balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        Ok(*self.account_balances.get(account).unwrap_or(&0))
    }

    fn min_balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        Ok(*self.account_min_balances.get(account).unwrap_or(&0))
    }

    fn asset_holding_get(
        &self,
        account: &[u8; 32],
        asset_id: u64,
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        if let Some(&(amount, frozen)) = self.asset_holdings.get(&(*account, asset_id)) {
            let val = match field {
                0 => TealValue::Uint(amount),        // AssetBalance
                1 => TealValue::Uint(frozen as u64), // AssetFrozen
                _ => {
                    return Err(AlgoError::Avm {
                        message: format!("unknown asset holding field: {field}"),
                    })
                }
            };
            Ok((val, true))
        } else {
            Ok((TealValue::Uint(0), false))
        }
    }

    fn asset_params_get(&self, asset_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        if let Some(creator) = self.asset_params.get(&asset_id) {
            // Return minimal params with correct types. Byte-typed fields
            // return empty bytes; uint-typed fields return 0.
            let val = match field {
                0 => TealValue::Uint(0),                 // AssetTotal
                1 => TealValue::Bytes(vec![]),           // AssetUnitName
                2 => TealValue::Bytes(vec![]),           // AssetName
                3 => TealValue::Bytes(vec![]),           // AssetURL
                4 => TealValue::Bytes(vec![]),           // AssetMetadataHash
                5 => TealValue::Bytes(creator.to_vec()), // AssetCreator
                6 => TealValue::Bytes(vec![0u8; 32]),    // AssetManager
                7 => TealValue::Bytes(vec![0u8; 32]),    // AssetReserve
                8 => TealValue::Bytes(vec![0u8; 32]),    // AssetFreeze
                9 => TealValue::Bytes(vec![0u8; 32]),    // AssetClawback
                10 => TealValue::Uint(0),                // AssetDecimals
                11 => TealValue::Uint(0),                // AssetDefaultFrozen
                _ => TealValue::Uint(0),
            };
            Ok((val, true))
        } else {
            Ok((TealValue::Uint(0), false))
        }
    }

    fn app_params_get(&self, app_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        if let Some((approval, clear, creator)) = self.app_params.get(&app_id) {
            let val = match field {
                0 => TealValue::Bytes(approval.clone()), // AppApprovalProgram
                1 => TealValue::Bytes(clear.clone()),    // AppClearStateProgram
                2 => TealValue::Uint(0),                 // AppGlobalNumUint
                3 => TealValue::Uint(0),                 // AppGlobalNumByteSlice
                4 => TealValue::Uint(0),                 // AppLocalNumUint
                5 => TealValue::Uint(0),                 // AppLocalNumByteSlice
                6 => TealValue::Uint(0),                 // AppExtraProgramPages
                7 => TealValue::Bytes(creator.to_vec()), // AppCreator
                8 => TealValue::Bytes(app_address(app_id).to_vec()), // AppAddress
                _ => TealValue::Uint(0),
            };
            Ok((val, true))
        } else {
            Ok((TealValue::Uint(0), false))
        }
    }

    fn acct_params_get(
        &self,
        account: &[u8; 32],
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        if let Some(&balance) = self.account_balances.get(account) {
            let val = match field {
                0 => TealValue::Uint(balance), // AcctBalance
                1 => TealValue::Uint(*self.account_min_balances.get(account).unwrap_or(&0)), // AcctMinBalance
                2 => TealValue::Bytes(vec![0u8; 32]), // AcctAuthAddr
                3 => TealValue::Uint(0),              // AcctTotalNumUint
                4 => TealValue::Uint(0),              // AcctTotalNumByteSlice
                5 => TealValue::Uint(0),              // AcctTotalExtraAppPages
                6 => TealValue::Uint(0),              // AcctTotalAppsCreated
                7 => TealValue::Uint(0),              // AcctTotalAppsOptedIn
                8 => TealValue::Uint(0),              // AcctTotalAssetsCreated
                9 => TealValue::Uint(0),              // AcctTotalAssets
                10 => TealValue::Uint(0),             // AcctTotalBoxes
                11 => TealValue::Uint(0),             // AcctTotalBoxBytes
                12 => TealValue::Uint(0),             // AcctIncentiveEligible
                13 => TealValue::Uint(0),             // AcctLastProposed
                14 => TealValue::Uint(0),             // AcctLastHeartbeat
                _ => TealValue::Uint(0),
            };
            Ok((val, true))
        } else {
            Ok((TealValue::Uint(0), false))
        }
    }

    // ---- Logging ----

    fn log(&mut self, data: Vec<u8>) -> Result<(), AlgoError> {
        self.logs.push(data);
        Ok(())
    }

    // ---- Group scratch space ----

    fn gload(&self, group_index: usize, slot: u8) -> Result<TealValue, AlgoError> {
        if group_index >= self.group_scratch.len() {
            return Ok(TealValue::Uint(0));
        }
        let scratch = &self.group_scratch[group_index];
        let slot = slot as usize;
        if slot >= scratch.len() {
            return Ok(TealValue::Uint(0));
        }
        match &scratch[slot] {
            AvmValue::Uint64(n) => Ok(TealValue::Uint(*n)),
            AvmValue::Bytes(b) => Ok(TealValue::Bytes(b.clone())),
        }
    }

    fn created_id(&self, _group_index: usize) -> Result<u64, AlgoError> {
        Ok(0)
    }

    fn block_field(&self, _round: u64, field: u8) -> Result<AvmValue, AlgoError> {
        // Dryrun does not have block history — return zero-value defaults
        // with correct types per go-algorand's blockFieldSpecs.
        match field {
            0 => Ok(AvmValue::Bytes(vec![0u8; 32])), // BlkSeed (VRF output)
            1 => Ok(AvmValue::Uint64(0)),            // BlkTimestamp
            2 => Ok(AvmValue::Bytes(vec![0u8; 32])), // BlkProposer (address)
            3 => Ok(AvmValue::Uint64(0)),            // BlkFeesCollected
            4 => Ok(AvmValue::Uint64(0)),            // BlkBonus
            5 => Ok(AvmValue::Bytes(vec![0u8; 32])), // BlkBranch (digest)
            6 => Ok(AvmValue::Bytes(vec![0u8; 32])), // BlkFeeSink (address)
            7 => Ok(AvmValue::Bytes(vec![])),        // BlkProtocol (string)
            8 => Ok(AvmValue::Uint64(0)),            // BlkTxnCounter
            9 => Ok(AvmValue::Uint64(0)),            // BlkProposerPayout
            _ => Ok(AvmValue::Uint64(0)),
        }
    }

    // ---- Inner transactions (not supported in basic dryrun) ----

    fn itxn_begin(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn itxn_field(&mut self, _field: u8, _value: TealValue) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn itxn_next(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn itxn_submit(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn last_itxn_field(
        &self,
        _field: u8,
        _array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn last_itxn_group_field(
        &self,
        _group_index: usize,
        _field: u8,
        _array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "inner transactions not supported in dryrun".into(),
        })
    }

    fn num_inner_txns(&self) -> usize {
        0
    }

    // ---- Execution mode / identity ----

    fn is_app_mode(&self) -> bool {
        self.app_mode
    }

    fn current_app_id(&self) -> u64 {
        self.app_id
    }

    fn program_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }

    fn caller_app_id(&self) -> u64 {
        0
    }

    fn caller_app_address(&self) -> [u8; 32] {
        [0u8; 32]
    }

    fn inner_txn_depth(&self) -> u32 {
        0
    }

    // ---- Box storage (not supported in basic dryrun) ----

    fn box_get(&mut self, _name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        Ok((vec![], false))
    }

    fn box_put(&mut self, _name: &[u8], _value: &[u8]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn box_del(&mut self, _name: &[u8]) -> Result<bool, AlgoError> {
        Ok(false)
    }

    fn box_len(&mut self, _name: &[u8]) -> Result<(u64, bool), AlgoError> {
        Ok((0, false))
    }

    fn box_create(&mut self, _name: &[u8], _size: u64) -> Result<bool, AlgoError> {
        Ok(false)
    }

    fn box_extract(
        &mut self,
        _name: &[u8],
        _offset: u64,
        _length: u64,
    ) -> Result<Vec<u8>, AlgoError> {
        Ok(vec![])
    }

    fn box_replace(&mut self, _name: &[u8], _offset: u64, _value: &[u8]) -> Result<(), AlgoError> {
        Ok(())
    }

    fn box_resize(&mut self, _name: &[u8], _new_size: u64) -> Result<(), AlgoError> {
        Ok(())
    }

    fn box_splice(
        &mut self,
        _name: &[u8],
        _start: u64,
        _length: u64,
        _value: &[u8],
    ) -> Result<(), AlgoError> {
        Ok(())
    }

    // ---- Resource availability ----

    fn is_asset_available(&self, asset_id: u64) -> bool {
        // Check foreign assets of current txn
        let txn = &self.group[self.group_index].txn;
        if let Some(ref assets) = txn.foreign_assets {
            if assets.contains(&asset_id) {
                return true;
            }
        }
        false
    }

    fn is_app_available(&self, app_id: u64) -> bool {
        if app_id == self.app_id {
            return true;
        }
        let txn = &self.group[self.group_index].txn;
        if let Some(ref apps) = txn.foreign_apps {
            if apps.contains(&app_id) {
                return true;
            }
        }
        false
    }

    // ---- Voter / stake queries ----

    fn voter_params_get(
        &self,
        _account: &[u8; 32],
        _field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        Ok((TealValue::Uint(0), false))
    }

    fn online_stake(&self) -> Result<u64, AlgoError> {
        // Match go-algorand's dryrunLedger.OnlineCirculation: Algos(1_000_000_000)
        // = 1,000,000,000 * 1,000,000 microAlgos
        Ok(1_000_000_000_000_000)
    }

    // ---- Result extraction ----

    fn take_logs(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.logs)
    }

    fn take_inner_transactions(&mut self) -> Vec<SignedTransaction> {
        Vec::new()
    }

    fn take_global_delta(&mut self) -> HashMap<Vec<u8>, Option<TealValue>> {
        self.global_deltas.remove(&self.app_id).unwrap_or_default()
    }

    fn take_local_deltas(&mut self) -> HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>> {
        let app_id = self.app_id;
        let mut result = HashMap::new();
        let keys: Vec<([u8; 32], u64)> = self
            .local_deltas
            .keys()
            .filter(|(_, aid)| *aid == app_id)
            .cloned()
            .collect();
        for (addr, _) in keys {
            if let Some(deltas) = self.local_deltas.remove(&(addr, app_id)) {
                result.insert(Address(addr), deltas);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// expand_sources — compile DryrunSource entries and patch into request
// ---------------------------------------------------------------------------

/// Compile DryrunSource entries and patch compiled bytecode into the request's
/// transactions or apps, matching go-algorand's `ExpandSources()`.
pub fn expand_sources(req: &mut DryrunRequest) -> Result<(), String> {
    let sources: Vec<DryrunSource> = std::mem::take(&mut req.sources);
    for (si, src) in sources.iter().enumerate() {
        let compiled = assemble_string(&src.source).map_err(|errs| {
            let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
            format!("dryrun Source[{si}]: {}", msgs.join("; "))
        })?;
        let program_bytes = compiled.program;

        match src.field_name.as_str() {
            "approv" => {
                // Find the app by app_index
                for app in &mut req.apps {
                    if app.id == src.app_index {
                        app.params.approval_program = program_bytes.clone();
                    }
                }
            }
            "clearp" => {
                for app in &mut req.apps {
                    if app.id == src.app_index {
                        app.params.clear_state_program = program_bytes.clone();
                    }
                }
            }
            "lsig" => {
                // Patch the logicsig program in the txn JSON
                let idx = src.txn_index;
                if idx >= req.txns.len() {
                    return Err(format!(
                        "dryrun Source[{si}]: txn index {} out of range ({})",
                        idx,
                        req.txns.len()
                    ));
                }
                {
                    let encoded = BASE64.encode(&program_bytes);
                    if let Some(obj) = req.txns[idx].as_object_mut() {
                        let lsig = obj.entry("lsig").or_insert_with(|| serde_json::json!({}));
                        if let Some(lsig_obj) = lsig.as_object_mut() {
                            lsig_obj.insert("l".to_string(), serde_json::Value::String(encoded));
                        }
                    }
                }
            }
            _ => {
                return Err(format!(
                    "dryrun Source[{si}]: bad field name {:?}",
                    src.field_name
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_dryrun_request — main execution loop
// ---------------------------------------------------------------------------

/// Convert internal state deltas to the API `StateDelta` format.
fn deltas_to_api_state_delta(deltas: &HashMap<Vec<u8>, Option<TealValue>>) -> StateDelta {
    let mut result: Vec<EvalDeltaKeyValue> = deltas
        .iter()
        .map(|(key, val)| {
            let key_b64 = BASE64.encode(key);
            // Go's DeltaAction: SetBytesAction=1, SetUintAction=2, DeleteAction=3
            let eval_delta = match val {
                Some(TealValue::Uint(n)) => ApiEvalDelta {
                    action: 2, // SetUintAction
                    bytes: None,
                    uint: Some(*n),
                },
                Some(TealValue::Bytes(b)) => ApiEvalDelta {
                    action: 1, // SetBytesAction
                    bytes: Some(BASE64.encode(b)),
                    uint: None,
                },
                None => ApiEvalDelta {
                    action: 3,
                    bytes: None,
                    uint: None,
                },
            };
            EvalDeltaKeyValue {
                key: key_b64,
                value: eval_delta,
            }
        })
        .collect();
    result.sort_by(|a, b| a.key.cmp(&b.key));
    result
}

/// Execute a dryrun request and return the response.
///
/// This is the main entry point, matching go-algorand's `doDryrunRequest()`.
pub fn do_dryrun_request(mut req: DryrunRequest) -> DryrunResponse {
    // Determine protocol version and consensus params
    let proto_version = if req.protocol_version.is_empty() {
        CONSENSUS_CURRENT_VERSION.to_string()
    } else {
        req.protocol_version.clone()
    };

    let consensus = match consensus_params_for_version(&proto_version) {
        Some(c) => c,
        None => {
            return DryrunResponse {
                error: format!("unsupported protocol version: {}", proto_version),
                protocol_version: proto_version,
                txns: Vec::new(),
            };
        }
    };

    // Expand sources (compile and patch)
    if let Err(e) = expand_sources(&mut req) {
        return DryrunResponse {
            error: e,
            protocol_version: proto_version,
            txns: Vec::new(),
        };
    }

    // Parse transactions from JSON
    let mut signed_txns: Vec<SignedTransaction> = Vec::new();
    for txn_val in &req.txns {
        match serde_json::from_value::<SignedTransaction>(txn_val.clone()) {
            Ok(stxn) => signed_txns.push(stxn),
            Err(e) => {
                return DryrunResponse {
                    error: format!("failed to parse transaction: {e}"),
                    protocol_version: proto_version,
                    txns: Vec::new(),
                };
            }
        }
    }

    // Execute each transaction.
    // Go dryrun uses an inflated budget: maxCurrentBudget = MaxAppProgramCost * 100
    // (= 70,000), independent of group size, so users can debug costly programs.
    let mut results = Vec::new();
    let mut group_budget = GroupBudget::new(100);

    // Build shared state once from the request data.
    let mut shared = DryrunSharedState::from_request(&req.accounts, &req.apps, signed_txns.len());

    for (i, stxn) in signed_txns.iter().enumerate() {
        let result = execute_single_txn(
            i,
            stxn,
            &signed_txns,
            &req.apps,
            req.round,
            req.latest_timestamp,
            &consensus,
            &mut group_budget,
            &mut shared,
        );
        results.push(result);
    }

    DryrunResponse {
        error: String::new(),
        protocol_version: proto_version,
        txns: results,
    }
}

/// Execute a single transaction in the dryrun.
///
/// State maps are swapped in from `shared` before execution and swapped back
/// afterwards, so mutations persist across transactions in the group.
#[allow(clippy::too_many_arguments)]
fn execute_single_txn(
    txn_index: usize,
    stxn: &SignedTransaction,
    group: &[SignedTransaction],
    apps: &[ApiApplication],
    round: u64,
    latest_timestamp: i64,
    consensus: &ConsensusParams,
    group_budget: &mut GroupBudget,
    shared: &mut DryrunSharedState,
) -> DryrunTxnResult {
    let txn = &stxn.txn;
    let is_app_call = txn.txn_type.as_str() == "appl";
    let has_lsig = stxn.lsig.is_some();

    let mut result = DryrunTxnResult {
        app_call_messages: None,
        app_call_trace: None,
        budget_added: None,
        budget_consumed: None,
        disassembly: Vec::new(),
        global_delta: None,
        local_deltas: None,
        logic_sig_disassembly: None,
        logic_sig_messages: None,
        logic_sig_trace: None,
        logs: None,
    };

    // --- LogicSig execution ---
    if has_lsig {
        let lsig = stxn.lsig.as_ref().unwrap();
        let program_bytes = lsig.logic.as_ref();

        let mut tracer = DryrunDebugReceiver::new();
        tracer.init_program(program_bytes);

        let mut ctx = DryrunAvmContext::new(
            group.to_vec(),
            txn_index,
            round,
            latest_timestamp,
            0, // no app for logicsig
            [0u8; 32],
            consensus.clone(),
            false,
        );
        // INVARIANT: restore_from_ctx MUST be called on ALL code paths below.
        shared.take_into_ctx(&mut ctx);

        // Set lsig args
        if let Some(ref args) = lsig.args {
            ctx.lsig_args = args.iter().map(|a| a.to_vec()).collect();
        }

        // LogicSig uses a separate budget from app calls (20,000 per txn in the
        // group), not the pooled app-call budget. Create a one-off logicsig budget.
        let mut lsig_budget = GroupBudget::for_logicsig(group.len());
        let lsig_result = run_logicsig_program_with_tracer(
            program_bytes,
            &mut ctx,
            &mut lsig_budget,
            &mut tracer,
        );

        // Store logicsig scratch for gload conformance (Go saves scratch
        // for all program types, even though gload is not allowed in ModeSig).
        // If this txn also has an app call, the app-call path below will
        // overwrite this with the app's final scratch, which is correct.
        if let Some(ref scratch) = tracer.final_scratch {
            if txn_index < ctx.group_scratch.len() {
                ctx.group_scratch[txn_index] = scratch.clone();
            }
        }

        shared.restore_from_ctx(&mut ctx);

        let disasm_lines: Vec<String> = tracer.disassembly_lines().to_vec();

        let mut messages = Vec::new();
        match lsig_result {
            Ok(pass) => {
                if pass {
                    messages.push("PASS".to_string());
                } else {
                    messages.push("REJECT".to_string());
                }
            }
            Err(e) => {
                messages.push("REJECT".to_string());
                messages.push(e.to_string());
            }
        }

        result.disassembly = disasm_lines.clone();
        result.logic_sig_disassembly = Some(disasm_lines);
        result.logic_sig_messages = Some(messages);
        result.logic_sig_trace = Some(tracer.history);
    }

    // --- Application call execution ---
    if is_app_call {
        let app_id = txn.application_id;
        let is_clear_state = txn.on_completion == ON_COMPLETION_CLEAR_STATE;

        // Resolve effective app ID.
        // Go (dryrun.go:478-485): for app creation (app_id == 0), use
        // dr.Apps[0].Id if the creator matches the sender.
        let mut effective_app_id = app_id;
        if app_id == 0 {
            let sender_str = txn.sender.to_algorand_string();
            if let Some(first_app) = apps.first() {
                if first_app.params.creator == sender_str {
                    effective_app_id = first_app.id;
                }
            }
        }

        // Look up the app's programs from the apps array (matching Go behavior).
        // Go always looks up programs from dr.Apps, never from the transaction.
        let mut found_app = false;
        let mut program_bytes = Vec::new();
        let mut creator = [0u8; 32];
        for app in apps {
            if app.id == effective_app_id {
                program_bytes = if is_clear_state {
                    app.params.clear_state_program.clone()
                } else {
                    app.params.approval_program.clone()
                };
                creator = Address::from_str(&app.params.creator)
                    .map(|a| a.0)
                    .unwrap_or([0u8; 32]);
                found_app = true;
                break;
            }
        }
        if !found_app {
            result.app_call_messages = Some(vec![format!(
                "uploaded state did not include app id {effective_app_id} referenced in txn[{txn_index}]"
            )]);
            result.disassembly = vec![];
            return result;
        }

        if program_bytes.is_empty() {
            let label = if is_clear_state {
                "clear state program"
            } else {
                "approval program"
            };
            result.app_call_messages = Some(vec![format!("{label} is empty")]);
            return result;
        }

        let mut tracer = DryrunDebugReceiver::new();
        tracer.init_program(&program_bytes);

        let mut ctx = DryrunAvmContext::new(
            group.to_vec(),
            txn_index,
            round,
            latest_timestamp,
            effective_app_id,
            creator,
            consensus.clone(),
            true,
        );
        // INVARIANT: take_into_ctx moves shared state into ctx. restore_from_ctx
        // MUST be called on ALL code paths below — do not add early returns.
        shared.take_into_ctx(&mut ctx);

        // OptIn: pre-create local state for sender (matching Go behavior)
        if txn.on_completion == ON_COMPLETION_OPT_IN {
            ctx.app_local_state
                .entry((txn.sender.0, effective_app_id))
                .or_default();
            let opted = ctx.opted_in_apps.entry(txn.sender.0).or_default();
            if !opted.contains(&effective_app_id) {
                opted.push(effective_app_id);
            }
        }

        let budget_before = group_budget.remaining();

        // Use run_approval_program_with_tracer for both approval and clear-state
        // programs in dryrun. Go's dryrun uses StatefulEval (pooled budget) for
        // both. Using the separate clear-state runner would create an isolated
        // budget and budget_consumed would always report 0.
        let app_result =
            run_approval_program_with_tracer(&program_bytes, &mut ctx, group_budget, &mut tracer);

        let budget_after = group_budget.remaining();
        let budget_consumed = if budget_before > budget_after {
            budget_before - budget_after
        } else {
            0
        };

        let disasm_lines: Vec<String> = tracer.disassembly_lines().to_vec();
        result.disassembly = disasm_lines;

        let mut messages = Vec::new();
        if is_clear_state {
            messages.push("ClearStateProgram".to_string());
        } else {
            messages.push("ApprovalProgram".to_string());
        }
        if tracer.passed {
            messages.push("PASS".to_string());
        } else {
            messages.push("REJECT".to_string());
        }
        if let Some(ref err) = tracer.error {
            messages.push(err.clone());
        }
        result.app_call_messages = Some(messages);

        result.app_call_trace = Some(tracer.history);

        // Budget tracking
        // Go: budgetAdded = proto.MaxAppProgramCost * numInnerTxns(delta)
        // Since dryrun doesn't support inner transactions, budget_added is always 0.
        result.budget_added = Some(0);
        result.budget_consumed = Some(budget_consumed as u64);

        // Use AvmResult for deltas/logs (fixes the delta drain bug where
        // run_approval_program_with_tracer calls take_global_delta/take_local_deltas/take_logs
        // which drains the maps before we can read them).
        if let Ok(ref avm_result) = app_result {
            // Collect logs from AvmResult
            if !avm_result.logs.is_empty() {
                result.logs = Some(avm_result.logs.clone());
            }

            // Collect global delta from AvmResult
            if !avm_result.global_delta.is_empty() {
                result.global_delta = Some(deltas_to_api_state_delta(&avm_result.global_delta));
            }

            // Collect local deltas from AvmResult
            let mut local_deltas_list: Vec<AccountStateDelta> = Vec::new();
            for (addr, deltas) in &avm_result.local_deltas {
                if !deltas.is_empty() {
                    local_deltas_list.push(AccountStateDelta {
                        address: addr.to_string(),
                        delta: deltas_to_api_state_delta(deltas),
                    });
                }
            }
            if !local_deltas_list.is_empty() {
                result.local_deltas = Some(local_deltas_list);
            }
        }

        // Store final scratch in shared state for gload support.
        // Note: on parse errors (the only Err case), final_scratch is None,
        // so group_scratch stays empty for that index — correct behavior.
        if let Some(ref scratch) = tracer.final_scratch {
            if txn_index < ctx.group_scratch.len() {
                ctx.group_scratch[txn_index] = scratch.clone();
            }
        }

        shared.restore_from_ctx(&mut ctx);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_avm::AvmValue;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Build an AccountResponse with sensible defaults.
    fn make_simple_account(address_str: &str, amount: u64) -> AccountResponse {
        AccountResponse {
            address: address_str.to_string(),
            amount,
            amount_without_pending_rewards: amount,
            apps_local_state: None,
            apps_total_extra_pages: None,
            apps_total_schema: None,
            assets: None,
            auth_addr: None,
            created_apps: None,
            created_assets: None,
            incentive_eligible: None,
            last_heartbeat: None,
            last_proposed: None,
            min_balance: 100_000,
            participation: None,
            pending_rewards: 0,
            reward_base: None,
            rewards: 0,
            round: 1,
            sig_type: None,
            status: "Offline".to_string(),
            total_apps_opted_in: 0,
            total_assets_opted_in: 0,
            total_box_bytes: None,
            total_boxes: None,
            total_created_apps: 0,
            total_created_assets: 0,
        }
    }

    /// Compile TEAL source and return an ApiApplication.
    fn make_app(
        id: u64,
        creator_str: &str,
        approval_teal: &str,
        clear_teal: &str,
    ) -> ApiApplication {
        let approval = assemble_string(approval_teal)
            .expect("approval TEAL should compile")
            .program;
        let clear = assemble_string(clear_teal)
            .expect("clear TEAL should compile")
            .program;
        ApiApplication {
            id,
            params: crate::models::ApiApplicationParams {
                approval_program: approval,
                clear_state_program: clear,
                creator: creator_str.to_string(),
                extra_program_pages: None,
                global_state: None,
                global_state_schema: None,
                local_state_schema: None,
                size_sponsor: None,
                version: None,
            },
        }
    }

    /// Build a JSON Value for an appl (app-call) signed transaction.
    fn make_app_call_txn_json(
        sender_bytes: &[u8; 32],
        app_id: u64,
        on_completion: u64,
    ) -> serde_json::Value {
        let snd: Vec<u8> = sender_bytes.to_vec();
        json!({
            "txn": {
                "type": "appl",
                "snd": snd,
                "apid": app_id,
                "apan": on_completion
            }
        })
    }

    /// Build a JSON Value for a pay signed transaction (no logicsig yet).
    fn make_pay_txn_json(sender_bytes: &[u8; 32]) -> serde_json::Value {
        let snd: Vec<u8> = sender_bytes.to_vec();
        json!({
            "txn": {
                "type": "pay",
                "snd": snd
            }
        })
    }

    /// A well-known sender address (all-1s) for testing.
    fn test_sender() -> [u8; 32] {
        [1u8; 32]
    }

    /// Algorand-string form of test_sender().
    fn test_sender_str() -> String {
        Address(test_sender()).to_algorand_string()
    }

    // -----------------------------------------------------------------------
    // expand_sources tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_expand_sources_approv() {
        let app = make_app(
            42,
            &test_sender_str(),
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let mut req = DryrunRequest {
            accounts: vec![],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![DryrunSource {
                app_index: 42,
                field_name: "approv".to_string(),
                source: "#pragma version 10\nint 99\nint 99\npop".to_string(),
                txn_index: 0,
            }],
            txns: vec![],
        };

        expand_sources(&mut req).expect("expand_sources should succeed");
        // The approval program should match the independently compiled source.
        let expected = assemble_string("#pragma version 10\nint 99\nint 99\npop")
            .unwrap()
            .program;
        assert_eq!(req.apps[0].params.approval_program, expected);
    }

    #[test]
    fn test_expand_sources_clearp() {
        let app = make_app(
            42,
            &test_sender_str(),
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let mut req = DryrunRequest {
            accounts: vec![],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![DryrunSource {
                app_index: 42,
                field_name: "clearp".to_string(),
                source: "#pragma version 10\nint 99\nint 99\npop".to_string(),
                txn_index: 0,
            }],
            txns: vec![],
        };

        expand_sources(&mut req).expect("expand_sources should succeed");
        let expected = assemble_string("#pragma version 10\nint 99\nint 99\npop")
            .unwrap()
            .program;
        assert_eq!(req.apps[0].params.clear_state_program, expected);
    }

    #[test]
    fn test_expand_sources_lsig() {
        let sender = test_sender();
        let txn_json = make_pay_txn_json(&sender);
        let mut req = DryrunRequest {
            accounts: vec![],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![DryrunSource {
                app_index: 0,
                field_name: "lsig".to_string(),
                source: "#pragma version 10\nint 1".to_string(),
                txn_index: 0,
            }],
            txns: vec![txn_json],
        };

        expand_sources(&mut req).expect("expand_sources should succeed");
        // The txn JSON should now have lsig.l
        let lsig_l = req.txns[0]["lsig"]["l"].as_str();
        assert!(
            lsig_l.is_some(),
            "lsig.l should be present after expand_sources"
        );
        // It should be valid base64
        let decoded = BASE64.decode(lsig_l.unwrap());
        assert!(decoded.is_ok(), "lsig.l should be valid base64");
    }

    #[test]
    fn test_expand_sources_bad_field() {
        let app = make_app(
            42,
            &test_sender_str(),
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let mut req = DryrunRequest {
            accounts: vec![],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![DryrunSource {
                app_index: 42,
                field_name: "badfield".to_string(),
                source: "#pragma version 10\nint 1".to_string(),
                txn_index: 0,
            }],
            txns: vec![],
        };

        let result = expand_sources(&mut req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad field name"));
    }

    #[test]
    fn test_expand_sources_lsig_out_of_range() {
        let mut req = DryrunRequest {
            accounts: vec![],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![DryrunSource {
                app_index: 0,
                field_name: "lsig".to_string(),
                source: "#pragma version 10\nint 1".to_string(),
                txn_index: 5, // out of range — no txns
            }],
            txns: vec![],
        };

        let result = expand_sources(&mut req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("txn index 5 out of range"));
    }

    // -----------------------------------------------------------------------
    // do_dryrun_request basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_approval_pass() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        let app = make_app(
            100,
            &creator_str,
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 100, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .app_call_messages
            .as_ref()
            .expect("should have messages");
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS in messages: {:?}",
            msgs
        );
        assert!(msgs.contains(&"ApprovalProgram".to_string()));
    }

    #[test]
    fn test_dryrun_approval_reject() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        let app = make_app(
            100,
            &creator_str,
            "#pragma version 10\nint 0",
            "#pragma version 10\nint 1",
        );
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 100, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .app_call_messages
            .as_ref()
            .expect("should have messages");
        assert!(
            msgs.contains(&"REJECT".to_string()),
            "expected REJECT in messages: {:?}",
            msgs
        );
    }

    #[test]
    fn test_dryrun_empty_txns() {
        let req = DryrunRequest {
            accounts: vec![],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty());
        assert!(resp.txns.is_empty());
    }

    // -----------------------------------------------------------------------
    // LogicSig tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_logicsig_pass() {
        let sender = test_sender();
        let program = assemble_string("#pragma version 10\nint 1")
            .unwrap()
            .program;
        let program_bytes: Vec<serde_json::Value> = program.iter().map(|b| json!(*b)).collect();

        let txn = json!({
            "txn": {
                "type": "pay",
                "snd": sender.to_vec(),
            },
            "lsig": {
                "l": program_bytes
            }
        });

        let account = make_simple_account(&test_sender_str(), 1_000_000);
        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .logic_sig_messages
            .as_ref()
            .expect("should have lsig messages");
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS: {:?}",
            msgs
        );
    }

    #[test]
    fn test_dryrun_logicsig_reject() {
        let sender = test_sender();
        let program = assemble_string("#pragma version 10\nint 0")
            .unwrap()
            .program;
        let program_bytes: Vec<serde_json::Value> = program.iter().map(|b| json!(*b)).collect();

        let txn = json!({
            "txn": {
                "type": "pay",
                "snd": sender.to_vec(),
            },
            "lsig": {
                "l": program_bytes
            }
        });

        let account = make_simple_account(&test_sender_str(), 1_000_000);
        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .logic_sig_messages
            .as_ref()
            .expect("should have lsig messages");
        assert!(
            msgs.contains(&"REJECT".to_string()),
            "expected REJECT: {:?}",
            msgs
        );
    }

    // -----------------------------------------------------------------------
    // Clear state program test
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_clear_state() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        let app = make_app(
            100,
            &creator_str,
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let account = make_simple_account(&creator_str, 1_000_000);
        // on_completion = 3 means ClearState
        let txn = make_app_call_txn_json(&sender, 100, ON_COMPLETION_CLEAR_STATE);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .app_call_messages
            .as_ref()
            .expect("should have messages");
        assert!(
            msgs.contains(&"ClearStateProgram".to_string()),
            "expected ClearStateProgram: {:?}",
            msgs
        );
        assert!(msgs.contains(&"PASS".to_string()));
    }

    // -----------------------------------------------------------------------
    // Delta collection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_global_delta() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        let teal = "#pragma version 10\nbyte \"key\"\nint 42\napp_global_put\nint 1";
        let app = make_app(100, &creator_str, teal, "#pragma version 10\nint 1");
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 100, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0].app_call_messages.as_ref().unwrap();
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS: {:?}",
            msgs
        );

        // Verify global_delta is populated from AvmResult
        let delta = resp.txns[0]
            .global_delta
            .as_ref()
            .expect("global_delta should be Some after fix");
        assert_eq!(delta.len(), 1, "should have exactly 1 delta entry");
        let entry = &delta[0];
        // key = base64("key")
        assert_eq!(entry.key, BASE64.encode(b"key"));
        assert_eq!(entry.value.action, 2, "action should be SetUint (2)");
        assert_eq!(entry.value.uint, Some(42), "uint should be 42");
    }

    #[test]
    fn test_dryrun_local_delta() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        // OptIn (on_completion=1) + write local state
        let teal = "#pragma version 10\nint 0\nbyte \"lkey\"\nint 7\napp_local_put\nint 1";
        let app = make_app(100, &creator_str, teal, "#pragma version 10\nint 1");
        let account = make_simple_account(&creator_str, 1_000_000);
        // OptIn so dryrun pre-creates local state
        let txn = make_app_call_txn_json(&sender, 100, ON_COMPLETION_OPT_IN);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0].app_call_messages.as_ref().unwrap();
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS: {:?}",
            msgs
        );

        // Verify local_deltas is populated from AvmResult
        let locals = resp.txns[0]
            .local_deltas
            .as_ref()
            .expect("local_deltas should be Some after fix");
        assert_eq!(locals.len(), 1, "should have exactly 1 local delta");
        let local = &locals[0];
        assert_eq!(local.delta.len(), 1, "should have 1 key-value delta");
        let kv = &local.delta[0];
        assert_eq!(kv.key, BASE64.encode(b"lkey"));
        assert_eq!(kv.value.action, 2, "action should be SetUint (2)");
        assert_eq!(kv.value.uint, Some(7), "uint should be 7");
    }

    // -----------------------------------------------------------------------
    // OptIn handling
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_optin() {
        let sender = test_sender();
        let creator_str = test_sender_str();
        // app_opted_in checks if sender is opted in; with on_completion=1,
        // dryrun pre-creates it. Use app index 0 which resolves to the
        // current app (100) via resolve_app.
        let teal = "#pragma version 10\nint 0\nint 0\napp_opted_in\nassert\nint 1";
        let app = make_app(100, &creator_str, teal, "#pragma version 10\nint 1");
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 100, ON_COMPLETION_OPT_IN);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        let msgs = resp.txns[0].app_call_messages.as_ref().unwrap();
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS (app_opted_in should return 1): {:?}",
            msgs
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_missing_app() {
        let sender = test_sender();
        let account = make_simple_account(&test_sender_str(), 1_000_000);
        // Reference app_id=999 which is not in the apps array
        let txn = make_app_call_txn_json(&sender, 999, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty()); // per-txn error, not top-level
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .app_call_messages
            .as_ref()
            .expect("should have messages");
        let joined = msgs.join(" ");
        assert!(
            joined.contains("did not include app id 999"),
            "expected missing app message: {:?}",
            msgs
        );
    }

    #[test]
    fn test_dryrun_invalid_protocol() {
        let req = DryrunRequest {
            accounts: vec![],
            apps: vec![],
            latest_timestamp: 0,
            protocol_version: "not-a-real-protocol-version".to_string(),
            round: 1,
            sources: vec![],
            txns: vec![],
        };

        let resp = do_dryrun_request(req);
        assert!(!resp.error.is_empty(), "should have a top-level error");
        assert!(resp.error.contains("unsupported protocol version"));
    }

    #[test]
    fn test_dryrun_app_creation() {
        // app_id=0 in txn, first app in apps array has matching creator
        // -> resolves to that app. Use a distinctive 3-instruction program
        // to verify the correct app was selected (not a trivial `int 1`).
        let sender = test_sender();
        let creator_str = test_sender_str();
        let app = make_app(
            200,
            &creator_str,
            "#pragma version 10\nint 42\npop\nint 1",
            "#pragma version 10\nint 1",
        );
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 0, 0); // app_id=0 -> creation

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 1);
        let msgs = resp.txns[0]
            .app_call_messages
            .as_ref()
            .expect("should have messages");
        assert!(
            msgs.contains(&"PASS".to_string()),
            "expected PASS for app creation: {:?}",
            msgs
        );
        // Verify the distinctive program was selected by checking the trace
        // has 3 entries (int 42, pop, int 1), not 1 (int 1).
        let trace = resp.txns[0]
            .app_call_trace
            .as_ref()
            .expect("should have trace");
        assert_eq!(
            trace.len(),
            3,
            "trace should have 3 entries (int 42, pop, int 1) proving correct app was selected"
        );
        // First instruction pushes 42
        assert_eq!(trace[0].stack.len(), 1);
        assert_eq!(trace[0].stack[0].uint, 42);
    }

    // -----------------------------------------------------------------------
    // DryrunDebugReceiver unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trim_scratch_all_zeros() {
        let scratch = vec![AvmValue::Uint64(0); 10];
        let result = DryrunDebugReceiver::trim_scratch(&scratch);
        assert!(result.is_none(), "all-zeros scratch should return None");
    }

    #[test]
    fn test_trim_scratch_with_values() {
        let mut scratch = vec![AvmValue::Uint64(0); 10];
        scratch[2] = AvmValue::Uint64(42);
        scratch[5] = AvmValue::Uint64(99);
        // Trailing zeros after index 5 should be trimmed
        let result = DryrunDebugReceiver::trim_scratch(&scratch);
        assert!(result.is_some());
        let trimmed = result.unwrap();
        assert_eq!(trimmed.len(), 6); // indices 0..=5
        assert_eq!(trimmed[2].uint, 42);
        assert_eq!(trimmed[5].uint, 99);
        assert_eq!(trimmed[0].uint, 0);
    }

    #[test]
    fn test_trim_scratch_with_bytes() {
        let mut scratch = vec![AvmValue::Uint64(0); 5];
        scratch[1] = AvmValue::Bytes(vec![1, 2, 3]);
        // Empty bytes at index 3 should be treated as zero
        scratch[3] = AvmValue::Bytes(vec![]);
        let result = DryrunDebugReceiver::trim_scratch(&scratch);
        assert!(result.is_some());
        let trimmed = result.unwrap();
        assert_eq!(trimmed.len(), 2); // indices 0..=1
        assert_eq!(trimmed[1].value_type, 1); // bytes type
    }

    #[test]
    fn test_trim_scratch_empty() {
        let scratch: Vec<AvmValue> = vec![];
        let result = DryrunDebugReceiver::trim_scratch(&scratch);
        assert!(result.is_none(), "empty scratch should return None");
    }

    #[test]
    fn test_tracer_records_trace() {
        // Run a simple program through do_dryrun and verify trace entries
        let sender = test_sender();
        let creator_str = test_sender_str();
        let app = make_app(
            100,
            &creator_str,
            "#pragma version 10\nint 1",
            "#pragma version 10\nint 1",
        );
        let account = make_simple_account(&creator_str, 1_000_000);
        let txn = make_app_call_txn_json(&sender, 100, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty());
        let trace = resp.txns[0]
            .app_call_trace
            .as_ref()
            .expect("should have trace");
        assert!(!trace.is_empty(), "trace should have entries");
        // `#pragma version 10\nint 1` has 1 instruction (int 1).
        // The trace should record exactly one step.
        assert_eq!(
            trace.len(),
            1,
            "should have exactly 1 trace entry for 1 instruction"
        );
        let entry = &trace[0];
        // Line should be 1 (line 0 is the pragma, line 1 is the first instruction)
        assert_eq!(entry.line, 1, "line should be 1 for the first instruction");
        // pc is the code-relative byte offset (offsets start at 0 after the version byte)
        assert_eq!(entry.pc, 0, "pc should be 0 for the first instruction");
        // Stack after `int 1` should contain [1]
        assert_eq!(entry.stack.len(), 1);
        assert_eq!(entry.stack[0].uint, 1);
    }

    // -----------------------------------------------------------------------
    // Cross-txn shared state tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dryrun_cross_txn_global_state() {
        // Txn 0: writes global key "xkey" = 100
        // Txn 1: reads global key "xkey" via app_global_get, asserts non-zero
        // Both should PASS, proving state from txn 0 is visible to txn 1.
        let sender = test_sender();
        let creator_str = test_sender_str();

        let teal_writer = "#pragma version 10\nbyte \"xkey\"\nint 100\napp_global_put\nint 1";
        // Use foreign app index 1 (= first foreign app = app 100) to read its state
        let teal_reader =
            "#pragma version 10\nint 1\nbyte \"xkey\"\napp_global_get_ex\nassert\nint 100\n==\nassert\nint 1";

        let app = make_app(100, &creator_str, teal_writer, "#pragma version 10\nint 1");
        let app2 = make_app(200, &creator_str, teal_reader, "#pragma version 10\nint 1");

        let account = make_simple_account(&creator_str, 1_000_000);

        // Txn 0 calls app 100 (writer), txn 1 calls app 200 (reader)
        // App 200 needs app 100 in foreign apps to read its state
        let txn0 = make_app_call_txn_json(&sender, 100, 0);
        let mut txn1 = make_app_call_txn_json(&sender, 200, 0);
        // Add app 100 as foreign app for txn 1
        txn1["txn"]["apfa"] = json!([100u64]);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app, app2],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn0, txn1],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 2);

        // Txn 0 should PASS
        let msgs0 = resp.txns[0].app_call_messages.as_ref().unwrap();
        assert!(
            msgs0.contains(&"PASS".to_string()),
            "txn 0 should PASS: {:?}",
            msgs0
        );

        // Txn 1 should PASS (it reads the state written by txn 0)
        let msgs1 = resp.txns[1].app_call_messages.as_ref().unwrap();
        assert!(
            msgs1.contains(&"PASS".to_string()),
            "txn 1 should PASS (cross-txn state read): {:?}",
            msgs1
        );
    }

    #[test]
    fn test_dryrun_gload() {
        // Txn 0: stores 77 in scratch slot 0
        // Txn 1: reads txn 0's scratch slot 0 via gload, asserts == 77
        // Both should PASS.
        let sender = test_sender();
        let creator_str = test_sender_str();

        let teal_store = "#pragma version 10\nint 77\nstore 0\nint 1";
        let teal_load = "#pragma version 10\ngload 0 0\nint 77\n==\nassert\nint 1";

        let app = make_app(100, &creator_str, teal_store, "#pragma version 10\nint 1");
        let app2 = make_app(200, &creator_str, teal_load, "#pragma version 10\nint 1");

        let account = make_simple_account(&creator_str, 1_000_000);

        let txn0 = make_app_call_txn_json(&sender, 100, 0);
        let txn1 = make_app_call_txn_json(&sender, 200, 0);

        let req = DryrunRequest {
            accounts: vec![account],
            apps: vec![app, app2],
            latest_timestamp: 0,
            protocol_version: String::new(),
            round: 1,
            sources: vec![],
            txns: vec![txn0, txn1],
        };

        let resp = do_dryrun_request(req);
        assert!(resp.error.is_empty(), "unexpected error: {}", resp.error);
        assert_eq!(resp.txns.len(), 2);

        // Txn 0 should PASS
        let msgs0 = resp.txns[0].app_call_messages.as_ref().unwrap();
        assert!(
            msgs0.contains(&"PASS".to_string()),
            "txn 0 should PASS: {:?}",
            msgs0
        );

        // Txn 1 should PASS (gload reads scratch from txn 0)
        let msgs1 = resp.txns[1].app_call_messages.as_ref().unwrap();
        assert!(
            msgs1.contains(&"PASS".to_string()),
            "txn 1 should PASS (gload from txn 0): {:?}",
            msgs1
        );
    }
}
