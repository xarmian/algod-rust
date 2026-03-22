//! Dryrun execution engine.
//!
//! Implements the `/v2/teal/dryrun` endpoint logic, matching go-algorand's
//! `dryrunRequest` / `doDryrunRequest` from `daemon/algod/api/server/v2/dryrun.go`.

use std::collections::HashMap;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use algo_avm::{
    assemble_string, disassemble, parse, run_approval_program_with_tracer,
    run_clear_state_program_with_tracer, run_logicsig_program_with_tracer, AvmContext, AvmValue,
    EvalTracer, GroupBudget, Program, ProgramType,
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

    // ---- Delta tracking ----
    /// Global state delta: app_id → (key → Option<TealValue>).
    pub global_deltas: HashMap<u64, HashMap<Vec<u8>, Option<TealValue>>>,
    /// Local state delta: (address, app_id) → (key → Option<TealValue>).
    pub local_deltas: HashMap<([u8; 32], u64), LocalDeltaMap>,
    /// Log messages.
    pub logs: Vec<Vec<u8>>,
}

impl DryrunAvmContext {
    /// Build a new context from dryrun request data for a specific transaction.
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
        accounts: &[AccountResponse],
        apps: &[ApiApplication],
    ) -> Self {
        let mut ctx = Self {
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
            global_deltas: HashMap::new(),
            local_deltas: HashMap::new(),
            logs: Vec::new(),
        };

        // Load accounts
        for acct in accounts {
            if let Ok(addr) = Address::from_str(&acct.address) {
                ctx.account_balances.insert(addr.0, acct.amount);
                ctx.account_min_balances.insert(addr.0, acct.min_balance);
                ctx.account_status.insert(addr.0, acct.status.clone());

                // Load asset holdings
                if let Some(ref assets) = acct.assets {
                    for holding in assets {
                        ctx.asset_holdings.insert(
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
                        ctx.app_local_state.insert((addr.0, local.id), kv);
                        ctx.opted_in_apps.entry(addr.0).or_default().push(local.id);
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
                        ctx.app_global_state.insert(app.id, global_state);
                        ctx.app_params.insert(
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
            ctx.app_params.entry(app.id).or_insert_with(|| {
                (
                    app.params.approval_program.clone(),
                    app.params.clear_state_program.clone(),
                    creator_addr,
                )
            });

            ctx.app_global_state.entry(app.id).or_insert_with(|| {
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

        ctx
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
            7 => Ok(TealValue::Uint(self.latest_timestamp as u64)),
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
        if self.asset_params.contains_key(&asset_id) {
            // Return minimal params — for full dryrun support more fields would
            // need to be stored; for now return the creator for field 5 and
            // zeros for others.
            let val = match field {
                5 => {
                    // AssetCreator
                    let creator = self.asset_params.get(&asset_id).unwrap();
                    TealValue::Bytes(creator.to_vec())
                }
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

    fn gload(&self, _group_index: usize, _slot: u8) -> Result<TealValue, AlgoError> {
        // Dryrun does not support cross-txn scratch reads
        Ok(TealValue::Uint(0))
    }

    fn created_id(&self, _group_index: usize) -> Result<u64, AlgoError> {
        Ok(0)
    }

    fn block_field(&self, _round: u64, _field: u8) -> Result<AvmValue, AlgoError> {
        // Dryrun does not have block history
        Err(AlgoError::Avm {
            message: "block field not available in dryrun".into(),
        })
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
        Ok(0)
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
            let eval_delta = match val {
                Some(TealValue::Uint(n)) => ApiEvalDelta {
                    action: 1,
                    bytes: None,
                    uint: Some(*n),
                },
                Some(TealValue::Bytes(b)) => ApiEvalDelta {
                    action: 2,
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

    // Execute each transaction
    let mut results = Vec::new();
    let mut group_budget = GroupBudget::new(signed_txns.len());

    for (i, stxn) in signed_txns.iter().enumerate() {
        let result = execute_single_txn(
            i,
            stxn,
            &signed_txns,
            &req.accounts,
            &req.apps,
            req.round,
            req.latest_timestamp,
            &consensus,
            &mut group_budget,
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
#[allow(clippy::too_many_arguments)]
fn execute_single_txn(
    txn_index: usize,
    stxn: &SignedTransaction,
    group: &[SignedTransaction],
    accounts: &[AccountResponse],
    apps: &[ApiApplication],
    round: u64,
    latest_timestamp: i64,
    consensus: &ConsensusParams,
    group_budget: &mut GroupBudget,
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
            accounts,
            apps,
        );

        // Set lsig args
        if let Some(ref args) = lsig.args {
            ctx.lsig_args = args.iter().map(|a| a.to_vec()).collect();
        }

        let lsig_result =
            run_logicsig_program_with_tracer(program_bytes, &mut ctx, group_budget, &mut tracer);

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

        // Determine which program to run
        let (program_bytes, creator) = if app_id == 0 {
            // App creation — program is in the transaction
            let prog = if is_clear_state {
                txn.clear_state_program
                    .as_ref()
                    .map(|b| b.to_vec())
                    .unwrap_or_default()
            } else {
                txn.approval_program
                    .as_ref()
                    .map(|b| b.to_vec())
                    .unwrap_or_default()
            };
            (prog, txn.sender.0)
        } else {
            // Look up the app's programs from apps array (matching Go behavior)
            let mut found_program = None;
            for app in apps {
                if app.id == app_id {
                    let prog = if is_clear_state {
                        app.params.clear_state_program.clone()
                    } else {
                        app.params.approval_program.clone()
                    };
                    found_program = Some((
                        prog,
                        Address::from_str(&app.params.creator)
                            .map(|a| a.0)
                            .unwrap_or([0u8; 32]),
                    ));
                    break;
                }
            }
            match found_program {
                Some(p) => p,
                None => {
                    result.app_call_messages =
                        Some(vec![format!(
                            "uploaded state did not include app id {app_id} referenced in txn[{txn_index}]"
                        )]);
                    result.disassembly = vec![];
                    return result;
                }
            }
        };

        if program_bytes.is_empty() {
            result.app_call_messages = Some(vec!["approval program is empty".to_string()]);
            return result;
        }

        let mut tracer = DryrunDebugReceiver::new();
        tracer.init_program(&program_bytes);

        let effective_app_id = if app_id == 0 {
            // For app creation, check if dr.Apps[0].creator matches sender
            if let Some(first_app) = apps.first() {
                let app_creator = Address::from_str(&first_app.params.creator)
                    .map(|a| a.0)
                    .unwrap_or([0u8; 32]);
                if app_creator == txn.sender.0 {
                    first_app.id
                } else {
                    1
                }
            } else {
                1
            }
        } else {
            app_id
        };

        let mut ctx = DryrunAvmContext::new(
            group.to_vec(),
            txn_index,
            round,
            latest_timestamp,
            effective_app_id,
            creator,
            consensus.clone(),
            true,
            accounts,
            apps,
        );

        // OptIn: pre-create local state for sender (matching Go behavior)
        if txn.on_completion == ON_COMPLETION_OPT_IN {
            ctx.app_local_state
                .entry((txn.sender.0, effective_app_id))
                .or_default();
            ctx.opted_in_apps
                .entry(txn.sender.0)
                .or_default()
                .push(effective_app_id);
        }

        let budget_before = group_budget.remaining();

        if is_clear_state {
            let _app_result = run_clear_state_program_with_tracer(
                &program_bytes,
                &mut ctx,
                consensus,
                &mut tracer,
            );
        } else {
            let _app_result = run_approval_program_with_tracer(
                &program_bytes,
                &mut ctx,
                group_budget,
                &mut tracer,
            );
        }

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
        result.budget_added = Some(algo_avm::APP_BUDGET_PER_CALL as u64);
        result.budget_consumed = Some(budget_consumed as u64);

        // Collect logs
        let logs = ctx.take_logs();
        if !logs.is_empty() {
            result.logs = Some(logs);
        }

        // Collect global delta
        let global_delta = ctx
            .global_deltas
            .remove(&effective_app_id)
            .unwrap_or_default();
        if !global_delta.is_empty() {
            result.global_delta = Some(deltas_to_api_state_delta(&global_delta));
        }

        // Collect local deltas
        let mut local_deltas_list: Vec<AccountStateDelta> = Vec::new();
        let local_keys: Vec<([u8; 32], u64)> = ctx
            .local_deltas
            .keys()
            .filter(|(_, aid)| *aid == effective_app_id)
            .cloned()
            .collect();
        for (addr, _) in local_keys {
            if let Some(deltas) = ctx.local_deltas.remove(&(addr, effective_app_id)) {
                if !deltas.is_empty() {
                    let addr_str = Address(addr).to_string();
                    local_deltas_list.push(AccountStateDelta {
                        address: addr_str,
                        delta: deltas_to_api_state_delta(&deltas),
                    });
                }
            }
        }
        if !local_deltas_list.is_empty() {
            result.local_deltas = Some(local_deltas_list);
        }
    }

    result
}
