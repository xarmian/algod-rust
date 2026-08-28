//! State access opcodes: app state read/write, balance, asset/app/account
//! parameter queries, log, and group scratch space.

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::fields::{AcctParamsField, AppParamsField, AssetHoldingField, AssetParamsField};
use crate::machine::{AvmMachine, AvmValue};

use super::helpers::{avm_to_teal, get_uint8, get_uint8_pair, teal_to_avm};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve an account from a stack value.
///
/// Per go-algorand, if the value is a uint64 it is treated as an index into
/// the accounts (`apat`) array (resolved via `ctx.resolve_account`). If it is
/// a 32-byte slice it is used as a raw address.
fn resolve_account(value: AvmValue, ctx: &dyn AvmContext) -> Result<[u8; 32], AlgoError> {
    match value {
        AvmValue::Uint64(idx) => ctx.resolve_account(idx),
        AvmValue::Bytes(b) if b.len() == 32 => {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&b);
            Ok(addr)
        }
        _ => Err(AlgoError::Avm {
            message: "invalid account reference: expected uint64 index or 32-byte address"
                .to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Balance / min_balance
// ---------------------------------------------------------------------------

/// `balance` (0x60): pop account, push balance in microAlgos.
pub fn op_balance(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let bal = ctx.balance(&addr)?;
    machine.push(AvmValue::Uint64(bal))
}

/// `min_balance` (0x78): pop account, push minimum balance.
pub fn op_min_balance(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let mb = ctx.min_balance(&addr)?;
    machine.push(AvmValue::Uint64(mb))
}

// ---------------------------------------------------------------------------
// App state reads
// ---------------------------------------------------------------------------

/// `app_opted_in` (0x61): pop app_id (foreign app ref index), pop account.
/// Push 1 if opted in, 0 otherwise.
pub fn op_app_opted_in(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let app_id_raw = machine.pop_uint()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let app_id = ctx.resolve_app(app_id_raw)?;
    let opted_in = ctx.app_opted_in(&addr, app_id)?;
    machine.push(AvmValue::Uint64(if opted_in { 1 } else { 0 }))
}

/// `app_local_get` (0x62): pop key (bytes), pop account. Push local state value
/// (or uint64(0) if not found).
pub fn op_app_local_get(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let app_id = ctx.current_app_id();
    match ctx.app_local_get(&addr, app_id, &key)? {
        Some(tv) => machine.push(teal_to_avm(tv)),
        None => machine.push(AvmValue::Uint64(0)),
    }
}

/// `app_local_get_ex` (0x63): pop key (bytes), pop app_id (foreign app ref index), pop account.
/// Push value (or uint64(0)), then push did_exist flag (1/0).
pub fn op_app_local_get_ex(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let app_id_raw = machine.pop_uint()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let app_id = ctx.resolve_app(app_id_raw)?;
    match ctx.app_local_get(&addr, app_id, &key)? {
        Some(tv) => {
            machine.push(teal_to_avm(tv))?;
            machine.push(AvmValue::Uint64(1))
        }
        None => {
            machine.push(AvmValue::Uint64(0))?;
            machine.push(AvmValue::Uint64(0))
        }
    }
}

/// `app_global_get` (0x64): pop key (bytes). Push global state value (or uint64(0)).
pub fn op_app_global_get(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let app_id = ctx.current_app_id();
    match ctx.app_global_get(app_id, &key)? {
        Some(tv) => machine.push(teal_to_avm(tv)),
        None => machine.push(AvmValue::Uint64(0)),
    }
}

/// `app_global_get_ex` (0x65): pop key (bytes), pop app_id (foreign app ref index).
/// Push value (or uint64(0)), then push did_exist flag (1/0).
pub fn op_app_global_get_ex(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let app_id_raw = machine.pop_uint()?;
    let app_id = ctx.resolve_app(app_id_raw)?;
    match ctx.app_global_get(app_id, &key)? {
        Some(tv) => {
            machine.push(teal_to_avm(tv))?;
            machine.push(AvmValue::Uint64(1))
        }
        None => {
            machine.push(AvmValue::Uint64(0))?;
            machine.push(AvmValue::Uint64(0))
        }
    }
}

// ---------------------------------------------------------------------------
// App state writes
// ---------------------------------------------------------------------------

/// `app_local_put` (0x66): pop value, pop key (bytes), pop account.
/// Write to local state.
pub fn op_app_local_put(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let value = machine.pop()?;
    let key = machine.pop_bytes()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let app_id = ctx.current_app_id();
    ctx.app_local_put(&addr, app_id, &key, avm_to_teal(value))
}

/// `app_global_put` (0x67): pop value, pop key (bytes). Write to global state.
pub fn op_app_global_put(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let value = machine.pop()?;
    let key = machine.pop_bytes()?;
    let app_id = ctx.current_app_id();
    ctx.app_global_put(app_id, &key, avm_to_teal(value))
}

/// `app_local_del` (0x68): pop key (bytes), pop account. Delete from local state.
pub fn op_app_local_del(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let app_id = ctx.current_app_id();
    ctx.app_local_del(&addr, app_id, &key)
}

/// `app_global_del` (0x69): pop key (bytes). Delete from global state.
pub fn op_app_global_del(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let key = machine.pop_bytes()?;
    let app_id = ctx.current_app_id();
    ctx.app_global_del(app_id, &key)
}

// ---------------------------------------------------------------------------
// Asset / App / Account parameter queries
// ---------------------------------------------------------------------------

/// `asset_holding_get` (0x70): 1 immediate (field). Pop asset_id (foreign asset ref index),
/// pop account. Push (value, did_exist).
pub fn op_asset_holding_get(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    // Validate field.
    let _field = AssetHoldingField::from_u8(field_byte)?;
    let asset_id_raw = machine.pop_uint()?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let asset_id = ctx.resolve_asset(asset_id_raw)?;
    let (value, exists) = ctx.asset_holding_get(&addr, asset_id, field_byte)?;
    machine.push(teal_to_avm(value))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

/// `asset_params_get` (0x71): 1 immediate (field). Pop asset_id (foreign asset ref index).
/// Push (value, did_exist).
pub fn op_asset_params_get(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let _field = AssetParamsField::from_u8(field_byte)?;
    let asset_id_raw = machine.pop_uint()?;
    let asset_id = ctx.resolve_asset(asset_id_raw)?;
    let (value, exists) = ctx.asset_params_get(asset_id, field_byte)?;
    machine.push(teal_to_avm(value))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

/// `app_params_get` (0x72): 1 immediate (field). Pop app_id (foreign app ref index).
/// Push (value, did_exist).
pub fn op_app_params_get(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;

    // Matches go-algorand's opAppParamsGet exactly (eval.go):
    //   fs, ok := appParamsFieldSpecByField(paramField)
    //   if !ok || fs.version > cx.version { error }
    // Below foreignBoxVersion this is a no-op for every currently-defined
    // field (all have version <= 5, the opcode's own gate), but AppVersion
    // (v12)/AppSizeSponsor/AppForeignBoxReads/AppFamilyBoxAccess (v13) now
    // need it to reject reads from a lower-versioned program.
    let field = AppParamsField::from_u8(field_byte)?;
    if field.version() > machine.version {
        return Err(AlgoError::Avm {
            message: format!("invalid app_params_get field {field_byte}"),
        });
    }

    let app_id_raw = machine.pop_uint()?;
    let app_id = ctx.resolve_app(app_id_raw)?;
    let (value, exists) = ctx.app_params_get(app_id, field_byte)?;
    machine.push(teal_to_avm(value))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

/// `app_params_set f` (0x76): 1 immediate (settable field). Pop a uint64
/// and set field `f` on the CURRENT app (`ctx.current_app_id()`).
///
/// Matches go-algorand's `opAppParamsSet` exactly (eval.go):
///   fs, ok := appParamsFieldSpecByField(paramField)
///   if !ok || fs.setVersion == 0 || fs.setVersion > cx.version { error }
///   ... dispatch on fs.field, else "immutable app_params_set field %s"
pub fn op_app_params_set(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let field = match AppParamsField::from_u8(field_byte) {
        Ok(f) if f.set_version() != 0 && f.set_version() <= machine.version => f,
        _ => {
            return Err(AlgoError::Avm {
                message: format!("invalid app_params_set field {field_byte}"),
            });
        }
    };

    let arg = machine.pop_uint()?;
    let app_id = ctx.current_app_id();
    match field {
        AppParamsField::AppForeignBoxReads => ctx.set_foreign_box_reads(app_id, arg != 0),
        AppParamsField::AppFamilyBoxAccess => ctx.set_family_box_access(app_id, arg != 0),
        // Unreachable with the current field table: every other field has
        // `set_version() == 0`, which is already rejected above as
        // "invalid app_params_set field N" before reaching this match.
        // Kept as defensive coverage (mirrors go-algorand's own switch
        // default), matching go's text for a field whose `setVersion` is
        // someday made nonzero without a dispatch arm added here.
        _ => Err(AlgoError::Avm {
            message: format!("immutable app_params_set field {field}"),
        }),
    }
}

/// `acct_params_get` (0x73): 1 immediate (field). Pop account.
/// Push (value, did_exist).
pub fn op_acct_params_get(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    let _field = AcctParamsField::from_u8(field_byte)?;
    let acct_val = machine.pop()?;
    let addr = resolve_account(acct_val, ctx)?;
    let (value, exists) = ctx.acct_params_get(&addr, field_byte)?;
    machine.push(teal_to_avm(value))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

/// `log` (0xb0): pop bytes from stack, append to log.
pub fn op_log(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let data = machine.pop_bytes()?;
    ctx.log(data)
}

// ---------------------------------------------------------------------------
// Group scratch space
// ---------------------------------------------------------------------------

/// `gload` (0x3a): 2 immediates (group_index, slot). Push scratch value.
pub fn op_gload(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let (group_index, slot) = get_uint8_pair(instruction)?;
    let value = ctx.gload("gload", group_index as usize, slot)?;
    machine.push(teal_to_avm(value))
}

/// `gloads` (0x3b): 1 immediate (slot). Pop group_index from stack. Push scratch value.
pub fn op_gloads(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let slot = get_uint8(instruction)?;
    let group_index = machine.pop_uint()? as usize;
    let value = ctx.gload("gloads", group_index, slot)?;
    machine.push(teal_to_avm(value))
}

/// `gloadss` (0xc4): Pop slot (uint64) and group_index (uint64) from stack.
/// Push scratch value. AVM v6+, Application mode only.
pub fn op_gloadss(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let slot_raw = machine.pop_uint()?;
    let group_index_raw = machine.pop_uint()?;
    if slot_raw >= 256 {
        return Err(AlgoError::Avm {
            message: format!("gloadss scratch index >= 256 ({})", slot_raw),
        });
    }
    let value = ctx.gload("gloadss", group_index_raw as usize, slot_raw as u8)?;
    machine.push(teal_to_avm(value))
}

// ---------------------------------------------------------------------------
// Group created IDs (gaid / gaids)
// ---------------------------------------------------------------------------

/// `gaid` (0x3c): 1 immediate (group_index). Push created asset/app ID.
/// AVM v4+, Application mode only.
pub fn op_gaid(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let group_index = get_uint8(instruction)? as usize;
    let id = ctx.created_id(group_index)?;
    machine.push(AvmValue::Uint64(id))
}

/// `gaids` (0x3d): Pop group_index from stack. Push created asset/app ID.
/// AVM v4+, Application mode only.
pub fn op_gaids(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let group_index = machine.pop_uint()? as usize;
    let id = ctx.created_id(group_index)?;
    machine.push(AvmValue::Uint64(id))
}

// ---------------------------------------------------------------------------
// Block field access
// ---------------------------------------------------------------------------

/// `block` (0xd1): 1 immediate (BlockField). Pop round from stack.
/// Push the requested block field value. AVM v7+.
pub fn op_block(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &dyn AvmContext,
) -> Result<(), AlgoError> {
    let field_byte = get_uint8(instruction)?;
    // Validate the field index is a known BlockField
    let _field = crate::fields::BlockField::from_u8(field_byte)?;
    let round = machine.pop_uint()?;
    let value = ctx.block_field(round, field_byte)?;
    machine.push(value)
}

// ---------------------------------------------------------------------------
// Box storage opcodes (v8+)
// ---------------------------------------------------------------------------

/// `box_create` (0xb9, v8+): pop size (uint), pop name (bytes).
/// Push 1 if newly created, 0 if already existed.
pub fn op_box_create(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let size = machine.pop_uint()?;
    let name = machine.pop_bytes()?;
    let created = ctx.box_create(&name, size)?;
    machine.push(AvmValue::Uint64(if created { 1 } else { 0 }))
}

/// `box_extract` (0xba, v8+): pop length (uint), pop offset (uint), pop name (bytes).
/// Push extracted bytes.
pub fn op_box_extract(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let length = machine.pop_uint()?;
    let offset = machine.pop_uint()?;
    let name = machine.pop_bytes()?;
    let bytes = ctx.box_extract(&name, offset, length)?;
    machine.push(AvmValue::Bytes(bytes))
}

/// `box_replace` (0xbb, v8+): pop value (bytes), pop offset (uint), pop name (bytes).
pub fn op_box_replace(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let value = machine.pop_bytes()?;
    let offset = machine.pop_uint()?;
    let name = machine.pop_bytes()?;
    ctx.box_replace(&name, offset, &value)
}

/// `box_del` (0xbc, v8+): pop name (bytes). Push 1 if existed, 0 otherwise.
pub fn op_box_del(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let name = machine.pop_bytes()?;
    let existed = ctx.box_del(&name)?;
    machine.push(AvmValue::Uint64(if existed { 1 } else { 0 }))
}

/// `box_len` (0xbd, v8+): pop name (bytes). Push length (uint), push exists (bool).
pub fn op_box_len(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let name = machine.pop_bytes()?;
    let (len, exists) = ctx.box_len(&name)?;
    machine.push(AvmValue::Uint64(len))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

/// `box_get` (0xbe, v8+): pop name (bytes). Push value (bytes, empty if not exists),
/// push exists (bool).
pub fn op_box_get(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let name = machine.pop_bytes()?;
    let (value, exists) = ctx.box_get(&name)?;
    machine.push(AvmValue::Bytes(value))?;
    machine.push(AvmValue::Uint64(if exists { 1 } else { 0 }))
}

/// `box_put` (0xbf, v8+): pop value (bytes), pop name (bytes).
pub fn op_box_put(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let value = machine.pop_bytes()?;
    let name = machine.pop_bytes()?;
    ctx.box_put(&name, &value)
}

/// `box_splice` (0xd2, v10+): pop replace (bytes), pop length (uint),
/// pop start (uint), pop name (bytes).
pub fn op_box_splice(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let replacement = machine.pop_bytes()?;
    let length = machine.pop_uint()?;
    let start = machine.pop_uint()?;
    let name = machine.pop_bytes()?;
    ctx.box_splice(&name, start, length, &replacement)
}

/// `box_resize` (0xd3, v10+): pop size (uint), pop name (bytes).
pub fn op_box_resize(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let size = machine.pop_uint()?;
    let name = machine.pop_bytes()?;
    ctx.box_resize(&name, size)
}

// ---------------------------------------------------------------------------
// voter_params_get (0x74), online_stake (0x75) — v11+
// ---------------------------------------------------------------------------

/// `voter_params_get` (0x74, v11+): pop account, push value + did_exist.
///
/// Reads voter parameters from the balance round (320 rounds back).
/// The immediate byte selects the field:
///   0 = VoterBalance (online stake in microAlgos, uint64)
///   1 = VoterIncentiveEligible (bool)
/// Pushes `(value, did_exist)` where did_exist is 1 if the account was
/// online at the balance round.
pub fn op_voter_params_get(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let field = get_uint8(instruction)?;
    let acct_val = machine.pop()?;
    let account = resolve_account(acct_val, ctx)?;
    let (value, exists) = ctx.voter_params_get(&account, field)?;
    machine.push(teal_to_avm(value))?;
    machine.push(AvmValue::Uint64(u64::from(exists)))
}

/// `online_stake` (0x75, v11+): push total online stake in microAlgos.
pub fn op_online_stake(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let amount = ctx.online_stake()?;
    machine.push(AvmValue::Uint64(amount))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::bytecode;
    use crate::context::AvmContext;
    use crate::machine::{AvmMachine, AvmValue, ExecMode};
    use crate::ops::helpers::prog;
    use algo_error::AlgoError;
    use algo_types::TealValue;
    use std::collections::HashMap;

    // --- Test context with pre-loaded state ---
    // Only overrides the methods actually used by state opcodes; everything
    // else falls through to the default "context unavailable" errors.

    struct TestStateContext {
        /// Accounts known to this context: index -> address
        accounts: Vec<[u8; 32]>,
        /// Current app ID.
        app_id: u64,
        /// Account balances: address -> balance
        balances: HashMap<[u8; 32], u64>,
        /// Account min balances: address -> min_balance
        min_balances: HashMap<[u8; 32], u64>,
        /// Global state: (app_id, key) -> TealValue
        global_state: HashMap<(u64, Vec<u8>), TealValue>,
        /// Local state: (account, app_id, key) -> TealValue
        local_state: HashMap<([u8; 32], u64, Vec<u8>), TealValue>,
        /// Opted-in: (account, app_id) -> bool
        opted_in: HashMap<([u8; 32], u64), bool>,
        /// Asset holdings: (account, asset_id, field) -> (TealValue, bool)
        asset_holdings: HashMap<([u8; 32], u64, u8), (TealValue, bool)>,
        /// Asset params: (asset_id, field) -> (TealValue, bool)
        asset_params: HashMap<(u64, u8), (TealValue, bool)>,
        /// App params: (app_id, field) -> (TealValue, bool)
        app_params: HashMap<(u64, u8), (TealValue, bool)>,
        /// Acct params: (account, field) -> (TealValue, bool)
        acct_params: HashMap<([u8; 32], u8), (TealValue, bool)>,
        /// Voter params: (account, field) -> (TealValue, bool)
        voter_params: HashMap<([u8; 32], u8), (TealValue, bool)>,
        /// Log messages collected.
        logs: Vec<Vec<u8>>,
        /// Group scratch: (group_index, slot) -> TealValue
        group_scratch: HashMap<(usize, u8), TealValue>,
        /// Created IDs: group_index -> created asset/app ID
        created_ids: HashMap<usize, u64>,
        /// Block fields: (round, field) -> AvmValue
        block_fields: HashMap<(u64, u8), AvmValue>,
        /// Group size override (for gaid tests).
        group_size_val: usize,
        /// Group index of the current transaction (for gaid tests).
        group_index_val: usize,
        /// Box storage: (name) -> contents
        boxes: HashMap<Vec<u8>, Vec<u8>>,
        /// Recorded `set_foreign_box_reads` calls: app_id -> enable.
        foreign_box_reads: HashMap<u64, bool>,
        /// Recorded `set_family_box_access` calls: app_id -> enable.
        family_box_access: HashMap<u64, bool>,
    }

    impl TestStateContext {
        fn new(app_id: u64) -> Self {
            Self {
                accounts: Vec::new(),
                app_id,
                balances: HashMap::new(),
                min_balances: HashMap::new(),
                global_state: HashMap::new(),
                local_state: HashMap::new(),
                opted_in: HashMap::new(),
                asset_holdings: HashMap::new(),
                asset_params: HashMap::new(),
                app_params: HashMap::new(),
                acct_params: HashMap::new(),
                voter_params: HashMap::new(),
                logs: Vec::new(),
                group_scratch: HashMap::new(),
                created_ids: HashMap::new(),
                block_fields: HashMap::new(),
                group_size_val: 1,
                group_index_val: 0,
                boxes: HashMap::new(),
                foreign_box_reads: HashMap::new(),
                family_box_access: HashMap::new(),
            }
        }
    }

    impl AvmContext for TestStateContext {
        fn group_size(&self) -> usize {
            self.group_size_val
        }

        fn group_index(&self) -> usize {
            self.group_index_val
        }

        fn resolve_account(&self, index: u64) -> Result<[u8; 32], AlgoError> {
            self.accounts
                .get(index as usize)
                .copied()
                .ok_or_else(|| AlgoError::Avm {
                    message: format!("account index {} out of range", index),
                })
        }

        fn resolve_asset(&self, index: u64) -> Result<u64, AlgoError> {
            Ok(index) // identity for tests
        }

        fn resolve_app(&self, index: u64) -> Result<u64, AlgoError> {
            if index == 0 {
                Ok(self.app_id) // 0 = current app
            } else {
                Ok(index) // identity for tests
            }
        }

        fn app_opted_in(&self, account: &[u8; 32], app_id: u64) -> Result<bool, AlgoError> {
            Ok(*self.opted_in.get(&(*account, app_id)).unwrap_or(&false))
        }

        fn app_local_get(
            &self,
            account: &[u8; 32],
            app_id: u64,
            key: &[u8],
        ) -> Result<Option<TealValue>, AlgoError> {
            Ok(self
                .local_state
                .get(&(*account, app_id, key.to_vec()))
                .cloned())
        }

        fn app_global_get(&self, app_id: u64, key: &[u8]) -> Result<Option<TealValue>, AlgoError> {
            Ok(self.global_state.get(&(app_id, key.to_vec())).cloned())
        }

        fn app_local_put(
            &mut self,
            account: &[u8; 32],
            app_id: u64,
            key: &[u8],
            value: TealValue,
        ) -> Result<(), AlgoError> {
            self.local_state
                .insert((*account, app_id, key.to_vec()), value);
            Ok(())
        }

        fn app_local_del(
            &mut self,
            account: &[u8; 32],
            app_id: u64,
            key: &[u8],
        ) -> Result<(), AlgoError> {
            self.local_state.remove(&(*account, app_id, key.to_vec()));
            Ok(())
        }

        fn app_global_put(
            &mut self,
            app_id: u64,
            key: &[u8],
            value: TealValue,
        ) -> Result<(), AlgoError> {
            self.global_state.insert((app_id, key.to_vec()), value);
            Ok(())
        }

        fn app_global_del(&mut self, app_id: u64, key: &[u8]) -> Result<(), AlgoError> {
            self.global_state.remove(&(app_id, key.to_vec()));
            Ok(())
        }

        fn balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
            self.balances
                .get(account)
                .copied()
                .ok_or_else(|| AlgoError::Avm {
                    message: "account not found".into(),
                })
        }

        fn min_balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
            self.min_balances
                .get(account)
                .copied()
                .ok_or_else(|| AlgoError::Avm {
                    message: "account not found".into(),
                })
        }

        fn asset_holding_get(
            &self,
            account: &[u8; 32],
            asset_id: u64,
            field: u8,
        ) -> Result<(TealValue, bool), AlgoError> {
            Ok(self
                .asset_holdings
                .get(&(*account, asset_id, field))
                .cloned()
                .unwrap_or((TealValue::Uint(0), false)))
        }

        fn asset_params_get(
            &self,
            asset_id: u64,
            field: u8,
        ) -> Result<(TealValue, bool), AlgoError> {
            Ok(self
                .asset_params
                .get(&(asset_id, field))
                .cloned()
                .unwrap_or((TealValue::Uint(0), false)))
        }

        fn app_params_get(&self, app_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
            Ok(self
                .app_params
                .get(&(app_id, field))
                .cloned()
                .unwrap_or((TealValue::Uint(0), false)))
        }

        fn acct_params_get(
            &self,
            account: &[u8; 32],
            field: u8,
        ) -> Result<(TealValue, bool), AlgoError> {
            Ok(self
                .acct_params
                .get(&(*account, field))
                .cloned()
                .unwrap_or((TealValue::Uint(0), false)))
        }

        fn voter_params_get(
            &self,
            account: &[u8; 32],
            field: u8,
        ) -> Result<(TealValue, bool), AlgoError> {
            Ok(self
                .voter_params
                .get(&(*account, field))
                .cloned()
                .unwrap_or((TealValue::Uint(0), false)))
        }

        fn log(&mut self, data: Vec<u8>) -> Result<(), AlgoError> {
            self.logs.push(data);
            Ok(())
        }

        fn gload(
            &self,
            op_name: &str,
            group_index: usize,
            slot: u8,
        ) -> Result<TealValue, AlgoError> {
            self.group_scratch
                .get(&(group_index, slot))
                .cloned()
                .ok_or_else(|| AlgoError::Avm {
                    message: format!(
                        "{op_name}: slot {} from group {} not found",
                        slot, group_index
                    ),
                })
        }

        fn created_id(&self, group_index: usize) -> Result<u64, AlgoError> {
            self.created_ids
                .get(&group_index)
                .copied()
                .ok_or_else(|| AlgoError::Avm {
                    message: format!("gaid: index {} did not create anything", group_index),
                })
        }

        fn block_field(&self, round: u64, field: u8) -> Result<AvmValue, AlgoError> {
            self.block_fields
                .get(&(round, field))
                .cloned()
                .ok_or_else(|| AlgoError::Avm {
                    message: format!(
                        "block field access not available (round={}, field={})",
                        round, field
                    ),
                })
        }

        fn is_app_mode(&self) -> bool {
            true
        }
        fn current_app_id(&self) -> u64 {
            self.app_id
        }

        fn set_foreign_box_reads(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
            self.foreign_box_reads.insert(app_id, enable);
            Ok(())
        }

        fn set_family_box_access(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
            self.family_box_access.insert(app_id, enable);
            Ok(())
        }

        fn box_get(&mut self, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
            match self.boxes.get(name) {
                Some(v) => Ok((v.clone(), true)),
                None => Ok((Vec::new(), false)),
            }
        }

        fn box_put(&mut self, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
            if name.is_empty() {
                return Err(AlgoError::Avm {
                    message: "box names may not be zero length".into(),
                });
            }
            self.boxes.insert(name.to_vec(), value.to_vec());
            Ok(())
        }

        fn box_del(&mut self, name: &[u8]) -> Result<bool, AlgoError> {
            Ok(self.boxes.remove(name).is_some())
        }

        fn box_len(&mut self, name: &[u8]) -> Result<(u64, bool), AlgoError> {
            match self.boxes.get(name) {
                Some(v) => Ok((v.len() as u64, true)),
                None => Ok((0, false)),
            }
        }

        fn box_create(&mut self, name: &[u8], size: u64) -> Result<bool, AlgoError> {
            if name.is_empty() {
                return Err(AlgoError::Avm {
                    message: "box names may not be zero length".into(),
                });
            }
            use std::collections::hash_map::Entry;
            match self.boxes.entry(name.to_vec()) {
                Entry::Occupied(_) => Ok(false),
                Entry::Vacant(e) => {
                    e.insert(vec![0u8; size as usize]);
                    Ok(true)
                }
            }
        }

        fn box_extract(
            &mut self,
            name: &[u8],
            offset: u64,
            length: u64,
        ) -> Result<Vec<u8>, AlgoError> {
            let contents = self.boxes.get(name).ok_or_else(|| AlgoError::Avm {
                message: format!("no such box {:?}", name),
            })?;
            let start = offset as usize;
            let end = start + length as usize;
            if end > contents.len() {
                return Err(AlgoError::Avm {
                    message: format!("extraction end {} beyond length: {}", end, contents.len()),
                });
            }
            Ok(contents[start..end].to_vec())
        }

        fn box_replace(&mut self, name: &[u8], offset: u64, value: &[u8]) -> Result<(), AlgoError> {
            let contents = self.boxes.get_mut(name).ok_or_else(|| AlgoError::Avm {
                message: format!("no such box {:?}", name),
            })?;
            let start = offset as usize;
            let end = start + value.len();
            if end > contents.len() {
                return Err(AlgoError::Avm {
                    message: format!("replacement end {} beyond length: {}", end, contents.len()),
                });
            }
            contents[start..end].copy_from_slice(value);
            Ok(())
        }

        fn box_resize(&mut self, name: &[u8], new_size: u64) -> Result<(), AlgoError> {
            let contents = self.boxes.get(name).ok_or_else(|| AlgoError::Avm {
                message: format!("no such box {:?}", name),
            })?;
            let mut resized = vec![0u8; new_size as usize];
            let copy_len = contents.len().min(new_size as usize);
            resized[..copy_len].copy_from_slice(&contents[..copy_len]);
            self.boxes.insert(name.to_vec(), resized);
            Ok(())
        }

        fn box_splice(
            &mut self,
            name: &[u8],
            start: u64,
            length: u64,
            value: &[u8],
        ) -> Result<(), AlgoError> {
            let contents = self.boxes.get(name).ok_or_else(|| AlgoError::Avm {
                message: format!("no such box {:?}", name),
            })?;
            let s = start as usize;
            if s > contents.len() {
                return Err(AlgoError::Avm {
                    message: format!("replacement start {} beyond length: {}", s, contents.len()),
                });
            }
            let oend = (start + length) as usize;
            if oend > contents.len() {
                return Err(AlgoError::Avm {
                    message: format!(
                        "splice end {} beyond original length: {}",
                        oend,
                        contents.len()
                    ),
                });
            }
            // Same-size splice per go-algorand behavior.
            let mut result = vec![0u8; contents.len()];
            result[..s].copy_from_slice(&contents[..s]);
            let copied = value.len().min(contents.len() - s);
            result[s..s + copied].copy_from_slice(&value[..copied]);
            let tail_start = s + copied;
            if tail_start < result.len() && oend < contents.len() {
                let tail_len = result.len() - tail_start;
                let avail = contents.len() - oend;
                let copy_len = tail_len.min(avail);
                result[tail_start..tail_start + copy_len]
                    .copy_from_slice(&contents[oend..oend + copy_len]);
            }
            self.boxes.insert(name.to_vec(), result);
            Ok(())
        }
    }

    // --- Test helpers ---

    /// Make a test address filled with a single byte value.
    fn test_addr(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    /// Step N instructions and return the machine.
    fn step_n(
        machine: &mut AvmMachine,
        ctx: &mut dyn AvmContext,
        n: usize,
    ) -> Result<(), AlgoError> {
        for _ in 0..n {
            machine.step(ctx)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Balance tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_balance_from_bytes() {
        // pushbytes <32-byte addr>, balance
        let addr = test_addr(0x01);
        let mut code = vec![0x80, 0x20]; // pushbytes, length=32
        code.extend_from_slice(&addr);
        code.push(0x60); // balance
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.balances.insert(addr, 5_000_000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(5_000_000));
    }

    #[test]
    fn test_balance_from_index() {
        // pushint 0, balance (index 0 -> accounts[0])
        let addr = test_addr(0x02);
        let raw = prog(5, &[0x81, 0x00, 0x60]); // pushint 0, balance
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.accounts.push(addr);
        ctx.balances.insert(addr, 1_000_000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1_000_000));
    }

    #[test]
    fn test_min_balance() {
        let addr = test_addr(0x03);
        let mut code = vec![0x80, 0x20]; // pushbytes, length=32
        code.extend_from_slice(&addr);
        code.push(0x78); // min_balance
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.min_balances.insert(addr, 100_000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(100_000));
    }

    // -----------------------------------------------------------------------
    // App opted-in tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_opted_in_true() {
        let addr = test_addr(0x04);
        // pushbytes addr, pushint 42, app_opted_in
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 42, 0x61]);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.opted_in.insert((addr, 42), true);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
    }

    #[test]
    fn test_app_opted_in_false() {
        let addr = test_addr(0x05);
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 42, 0x61]);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        // Not inserting opted_in -> defaults to false
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
    }

    // -----------------------------------------------------------------------
    // App local get/put/del tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_local_get_found() {
        let addr = test_addr(0x06);
        // pushbytes addr, pushbytes "mykey", app_local_get
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x05]); // pushbytes len=5
        code.extend_from_slice(b"mykey");
        code.push(0x62); // app_local_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.local_state
            .insert((addr, 100, b"mykey".to_vec()), TealValue::Uint(999));
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(999));
    }

    #[test]
    fn test_app_local_get_not_found() {
        let addr = test_addr(0x07);
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x05]);
        code.extend_from_slice(b"mykey");
        code.push(0x62);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
    }

    #[test]
    fn test_app_local_get_ex_found() {
        let addr = test_addr(0x08);
        // pushbytes addr, pushint 100, pushbytes "k", app_local_get_ex
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 100]); // pushint 100 (app_id)
        code.extend_from_slice(&[0x80, 0x01]); // pushbytes len=1
        code.push(b'k');
        code.push(0x63); // app_local_get_ex
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.local_state
            .insert((addr, 100, b"k".to_vec()), TealValue::Uint(42));
        step_n(&mut m, &mut ctx, 4).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(42)); // value
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // did_exist
    }

    #[test]
    fn test_app_local_get_ex_not_found() {
        let addr = test_addr(0x09);
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 100]);
        code.extend_from_slice(&[0x80, 0x01]);
        code.push(b'k');
        code.push(0x63);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 4).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // default value
        assert_eq!(m.stack[1], AvmValue::Uint64(0)); // did_exist = false
    }

    // -----------------------------------------------------------------------
    // App global get/put/del tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_global_get_found() {
        // pushbytes "counter", app_global_get
        let mut code = vec![0x80, 0x07]; // pushbytes len=7
        code.extend_from_slice(b"counter");
        code.push(0x64); // app_global_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.global_state
            .insert((100, b"counter".to_vec()), TealValue::Uint(7));
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(7));
    }

    #[test]
    fn test_app_global_get_not_found() {
        let mut code = vec![0x80, 0x07];
        code.extend_from_slice(b"counter");
        code.push(0x64);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
    }

    #[test]
    fn test_app_global_get_ex_found() {
        // pushint 100, pushbytes "k", app_global_get_ex
        let mut code = vec![0x81, 100]; // pushint 100
        code.extend_from_slice(&[0x80, 0x01]); // pushbytes len=1
        code.push(b'k');
        code.push(0x65); // app_global_get_ex
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.global_state
            .insert((100, b"k".to_vec()), TealValue::Bytes(b"val".to_vec()));
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"val".to_vec())); // value
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // did_exist
    }

    #[test]
    fn test_app_global_get_ex_not_found() {
        let mut code = vec![0x81, 100];
        code.extend_from_slice(&[0x80, 0x01]);
        code.push(b'k');
        code.push(0x65);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
        assert_eq!(m.stack[1], AvmValue::Uint64(0));
    }

    // -----------------------------------------------------------------------
    // State write tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_global_put_and_get() {
        // pushbytes "counter", pushint 42, app_global_put
        // pushbytes "counter", app_global_get
        let mut code = vec![];
        code.extend_from_slice(&[0x80, 0x07]); // pushbytes "counter"
        code.extend_from_slice(b"counter");
        code.extend_from_slice(&[0x81, 42]); // pushint 42
        code.push(0x67); // app_global_put
        code.extend_from_slice(&[0x80, 0x07]); // pushbytes "counter"
        code.extend_from_slice(b"counter");
        code.push(0x64); // app_global_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 5).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    #[test]
    fn test_app_global_del() {
        let mut code = vec![];
        // First put a value
        code.extend_from_slice(&[0x80, 0x01]); // pushbytes "k"
        code.push(b'k');
        code.extend_from_slice(&[0x81, 99]); // pushint 99
        code.push(0x67); // app_global_put
                         // Then delete it
        code.extend_from_slice(&[0x80, 0x01]); // pushbytes "k"
        code.push(b'k');
        code.push(0x69); // app_global_del
                         // Then get it (should be 0)
        code.extend_from_slice(&[0x80, 0x01]); // pushbytes "k"
        code.push(b'k');
        code.push(0x64); // app_global_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 7).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
    }

    #[test]
    fn test_app_local_put_and_get() {
        let addr = test_addr(0x0A);
        // pushbytes addr, pushbytes "key", pushint 77, app_local_put
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x03]);
        code.extend_from_slice(b"key");
        code.extend_from_slice(&[0x81, 77]);
        code.push(0x66); // app_local_put
                         // pushbytes addr, pushbytes "key", app_local_get
        code.extend_from_slice(&[0x80, 0x20]);
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x03]);
        code.extend_from_slice(b"key");
        code.push(0x62); // app_local_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 7).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(77));
    }

    #[test]
    fn test_app_local_del() {
        let addr = test_addr(0x0B);
        let mut ctx = TestStateContext::new(100);
        ctx.local_state
            .insert((addr, 100, b"x".to_vec()), TealValue::Uint(50));
        // pushbytes addr, pushbytes "x", app_local_del
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x01]);
        code.push(b'x');
        code.push(0x68); // app_local_del
                         // pushbytes addr, pushbytes "x", app_local_get
        code.extend_from_slice(&[0x80, 0x20]);
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x80, 0x01]);
        code.push(b'x');
        code.push(0x62); // app_local_get
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 6).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
    }

    // -----------------------------------------------------------------------
    // Asset / App / Account param query tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_asset_holding_get_exists() {
        let addr = test_addr(0x0C);
        let mut ctx = TestStateContext::new(100);
        // field 0 = AssetBalance
        ctx.asset_holdings
            .insert((addr, 42, 0), (TealValue::Uint(1000), true));
        // pushbytes addr, pushint 42, asset_holding_get AssetBalance
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 42]); // pushint 42
        code.extend_from_slice(&[0x70, 0x00]); // asset_holding_get field=0
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(1000)); // value
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // exists
    }

    #[test]
    fn test_asset_holding_get_not_exists() {
        let addr = test_addr(0x0D);
        let ctx = TestStateContext::new(100);
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 42]);
        code.extend_from_slice(&[0x70, 0x00]);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx_mut = ctx;
        step_n(&mut m, &mut ctx_mut, 3).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // default
        assert_eq!(m.stack[1], AvmValue::Uint64(0)); // not exists
    }

    #[test]
    fn test_asset_params_get() {
        let mut ctx = TestStateContext::new(100);
        // field 0 = AssetTotal
        ctx.asset_params
            .insert((99, 0), (TealValue::Uint(1_000_000), true));
        // pushint 99, asset_params_get AssetTotal
        let code = vec![0x81, 99, 0x71, 0x00];
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(1_000_000));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    #[test]
    fn test_app_params_get() {
        let mut ctx = TestStateContext::new(100);
        // field 7 = AppCreator
        ctx.app_params
            .insert((50, 7), (TealValue::Bytes(vec![0xAA; 32]), true));
        // pushint 50, app_params_get AppCreator
        let code = vec![0x81, 50, 0x72, 0x07];
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Bytes(vec![0xAA; 32]));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    /// v13 program reading `AppForeignBoxReads`/`AppFamilyBoxAccess` (fields
    /// 11/12, `foreignBoxVersion`) via `app_params_get` -- new in v5.0.0.
    #[test]
    fn test_app_params_get_foreign_box_fields() {
        let mut ctx = TestStateContext::new(100);
        ctx.app_params.insert((50, 11), (TealValue::Uint(1), true)); // AppForeignBoxReads
        ctx.app_params.insert((50, 12), (TealValue::Uint(0), true)); // AppFamilyBoxAccess
                                                                     // pushint 50, app_params_get AppForeignBoxReads
        let code = vec![0x81, 50, 0x72, 0x0b];
        let raw = prog(13, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    /// Below `foreignBoxVersion` (13), `app_params_get AppForeignBoxReads`
    /// must be rejected even though the opcode itself only requires v5 --
    /// go-algorand gates per-field, not just per-opcode
    /// (`appParamsFieldSpecs[AppForeignBoxReads].version == foreignBoxVersion`).
    #[test]
    fn test_app_params_get_foreign_box_field_rejected_below_v13() {
        let mut ctx = TestStateContext::new(100);
        ctx.app_params.insert((50, 11), (TealValue::Uint(1), true));
        let code = vec![0x81, 50, 0x72, 0x0b];
        let raw = prog(12, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap(); // pushint 50
        let err = m.step(&mut ctx).unwrap_err();
        assert!(
            err.to_string().contains("invalid app_params_get field 11"),
            "unexpected error: {err}"
        );
    }

    /// `AppVersion` (field 9) requires v12; a v11 program must reject it.
    #[test]
    fn test_app_params_get_app_version_field_rejected_below_v12() {
        let mut ctx = TestStateContext::new(100);
        ctx.app_params.insert((50, 9), (TealValue::Uint(3), true));
        let code = vec![0x81, 50, 0x72, 0x09];
        let raw = prog(11, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap();
        let err = m.step(&mut ctx).unwrap_err();
        assert!(
            err.to_string().contains("invalid app_params_get field 9"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_app_params_set_foreign_box_reads() {
        let mut ctx = TestStateContext::new(50);
        // pushint 1, app_params_set AppForeignBoxReads (field 11)
        let code = vec![0x81, 0x01, 0x76, 0x0b];
        let raw = prog(13, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert!(m.stack.is_empty(), "app_params_set pushes nothing");
        assert_eq!(ctx.foreign_box_reads.get(&50), Some(&true));
    }

    #[test]
    fn test_app_params_set_family_box_access() {
        let mut ctx = TestStateContext::new(50);
        // pushint 0, app_params_set AppFamilyBoxAccess (field 12)
        let code = vec![0x81, 0x00, 0x76, 0x0c];
        let raw = prog(13, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(ctx.family_box_access.get(&50), Some(&false));
    }

    /// `app_params_set` on a field whose `setVersion` is 0 (i.e. every
    /// field except `AppForeignBoxReads`/`AppFamilyBoxAccess`, e.g.
    /// `AppCreator`, field 7) must be rejected with the numeric-field
    /// "invalid" error -- matches go-algorand's `opAppParamsSet` exactly:
    /// the `fs.setVersion == 0` check happens *before* the field-dispatch
    /// switch, so a getVersion-only field never reaches the switch's
    /// `default: "immutable app_params_set field %s"` arm. That arm is
    /// unreachable with go-algorand's current field table (kept only as
    /// defensive coverage for a future field with a nonzero `setVersion`
    /// that the switch hasn't been taught to handle yet) -- see
    /// `crate::ops::state::op_app_params_set`'s own match for the mirror.
    #[test]
    fn test_app_params_set_non_settable_field_rejected() {
        let mut ctx = TestStateContext::new(50);
        // pushint 1, app_params_set AppCreator (field 7)
        let code = vec![0x81, 0x01, 0x76, 0x07];
        let raw = prog(13, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap(); // pushint 1
        let err = m.step(&mut ctx).unwrap_err();
        assert!(
            err.to_string().contains("invalid app_params_set field 7"),
            "unexpected error: {err}"
        );
    }

    /// An unknown field index must be rejected with the numeric-field error
    /// text (go: "invalid app_params_set field %d").
    #[test]
    fn test_app_params_set_unknown_field_rejected() {
        let mut ctx = TestStateContext::new(50);
        let code = vec![0x81, 0x01, 0x76, 0x63]; // field 99: unknown
        let raw = prog(13, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap();
        let err = m.step(&mut ctx).unwrap_err();
        assert!(
            err.to_string().contains("invalid app_params_set field 99"),
            "unexpected error: {err}"
        );
    }

    /// `app_params_set` is version-gated by the *program's* AVM version
    /// against the whole opcode's own version (`foreignBoxVersion` = 13),
    /// so the opcode byte itself is already rejected by the decoder at
    /// v12 -- this pins that at the bytecode-parse layer.
    #[test]
    fn test_app_params_set_opcode_rejected_below_v13() {
        let code = vec![0x81, 0x01, 0x76, 0x0b];
        let raw = prog(12, &code);
        let err = bytecode::parse(&raw).unwrap_err();
        assert!(
            err.to_string().contains("app_params_set"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_acct_params_get() {
        let addr = test_addr(0x0E);
        let mut ctx = TestStateContext::new(100);
        // field 0 = AcctBalance
        ctx.acct_params
            .insert((addr, 0), (TealValue::Uint(9_000_000), true));
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x73, 0x00]); // acct_params_get AcctBalance
        let raw = prog(6, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(9_000_000));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    // -----------------------------------------------------------------------
    // Log test
    // -----------------------------------------------------------------------

    #[test]
    fn test_log() {
        // pushbytes "hello", log
        let mut code = vec![0x80, 0x05];
        code.extend_from_slice(b"hello");
        code.push(0xb0); // log
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 0);
        assert_eq!(ctx.logs, vec![b"hello".to_vec()]);
    }

    // -----------------------------------------------------------------------
    // Group scratch space tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gload() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_scratch.insert((1, 5), TealValue::Uint(999));
        // gload 1 5 (group_index=1, slot=5)
        let code = vec![0x3a, 0x01, 0x05];
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(999));
    }

    #[test]
    fn test_gloads() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_scratch
            .insert((2, 3), TealValue::Bytes(b"data".to_vec()));
        // pushint 2, gloads 3 (pop group_index=2, slot=3)
        let code = vec![0x81, 0x02, 0x3b, 0x03];
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"data".to_vec()));
    }

    // -----------------------------------------------------------------------
    // Account resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_account_resolution_index() {
        let addr = test_addr(0x10);
        let mut ctx = TestStateContext::new(100);
        ctx.accounts.push(addr);
        ctx.balances.insert(addr, 2_000_000);
        // pushint 0, balance (resolve index 0 -> accounts[0])
        let code = vec![0x81, 0x00, 0x60];
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack[0], AvmValue::Uint64(2_000_000));
    }

    #[test]
    fn test_account_resolution_invalid_bytes() {
        // pushbytes with 16 bytes (not 32) -> should error
        let mut code = vec![0x80, 0x10]; // pushbytes len=16
        code.extend_from_slice(&[0xAA; 16]);
        code.push(0x60); // balance
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        step_n(&mut m, &mut ctx, 1).unwrap(); // pushbytes succeeds
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("invalid account reference"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // app_id=0 resolution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_opted_in_zero_app_id_resolves_to_current() {
        let addr = test_addr(0x11);
        let mut ctx = TestStateContext::new(100);
        ctx.opted_in.insert((addr, 100), true);
        // pushbytes addr, pushint 0, app_opted_in
        // app_id=0 should resolve to current_app_id=100
        let mut code = vec![0x80, 0x20];
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x81, 0x00, 0x61]);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
    }

    #[test]
    fn test_app_global_get_ex_zero_app_id() {
        let mut ctx = TestStateContext::new(100);
        ctx.global_state
            .insert((100, b"k".to_vec()), TealValue::Uint(55));
        // pushint 0 (app_id=0 -> current=100), pushbytes "k", app_global_get_ex
        let mut code = vec![0x81, 0x00];
        code.extend_from_slice(&[0x80, 0x01]);
        code.push(b'k');
        code.push(0x65);
        let raw = prog(5, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(55));
        assert_eq!(m.stack[1], AvmValue::Uint64(1));
    }

    // -----------------------------------------------------------------------
    // gaid / gaids tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gaid() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_size_val = 3;
        ctx.group_index_val = 2;
        ctx.created_ids.insert(0, 42);
        // gaid 0 (immediate group_index=0)
        let code = vec![0x3c, 0x00];
        let raw = prog(4, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(42));
    }

    #[test]
    fn test_gaid_not_found() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_size_val = 3;
        ctx.group_index_val = 2;
        // No created IDs inserted
        let code = vec![0x3c, 0x00];
        let raw = prog(4, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("did not create anything"), "got: {msg}");
    }

    #[test]
    fn test_gaids() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_size_val = 3;
        ctx.group_index_val = 2;
        ctx.created_ids.insert(1, 999);
        // pushint 1, gaids (pop group_index=1)
        let code = vec![0x81, 0x01, 0x3d];
        let raw = prog(4, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(999));
    }

    #[test]
    fn test_gaids_not_found() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_size_val = 3;
        ctx.group_index_val = 2;
        // pushint 0, gaids
        let code = vec![0x81, 0x00, 0x3d];
        let raw = prog(4, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 1).unwrap(); // pushint succeeds
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("did not create anything"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // gloadss tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gloadss() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_scratch.insert((1, 7), TealValue::Uint(12345));
        // pushint 1 (group_index), pushint 7 (slot), gloadss
        let code = vec![0x81, 0x01, 0x81, 0x07, 0xc4];
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(12345));
    }

    #[test]
    fn test_gloadss_bytes_value() {
        let mut ctx = TestStateContext::new(100);
        ctx.group_scratch
            .insert((0, 3), TealValue::Bytes(b"hello".to_vec()));
        // pushint 0 (group_index), pushint 3 (slot), gloadss
        let code = vec![0x81, 0x00, 0x81, 0x03, 0xc4];
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"hello".to_vec()));
    }

    #[test]
    fn test_gloadss_slot_too_large() {
        let mut ctx = TestStateContext::new(100);
        // pushint 0 (group_index), pushint 256 (slot >= 256 -> error), gloadss
        // 256 = 0x80 0x02 in varuint encoding
        let code = vec![0x81, 0x80, 0x02, 0x81, 0x00, 0x4c, 0xc4]; // pushint 256, pushint 0, swap, gloadss
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        // pushint 256, pushint 0, swap (now stack = [0, 256])
        step_n(&mut m, &mut ctx, 3).unwrap();
        let result = m.step(&mut ctx); // gloadss
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("scratch index >= 256"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // block tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_block_timestamp() {
        let mut ctx = TestStateContext::new(100);
        // BlkTimestamp = field 1
        ctx.block_fields
            .insert((99, 1), AvmValue::Uint64(1700000000));
        // pushint 99 (round), block 1 (BlkTimestamp)
        let code = vec![0x81, 99, 0xd1, 0x01];
        let raw = prog(7, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1700000000));
    }

    #[test]
    fn test_block_seed() {
        let mut ctx = TestStateContext::new(100);
        let seed = vec![0xAB; 32];
        // BlkSeed = field 0
        ctx.block_fields
            .insert((50, 0), AvmValue::Bytes(seed.clone()));
        // pushint 50 (round), block 0 (BlkSeed)
        let code = vec![0x81, 50, 0xd1, 0x00];
        let raw = prog(7, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(seed));
    }

    #[test]
    fn test_block_not_available() {
        let mut ctx = TestStateContext::new(100);
        // No block fields inserted -> error
        // pushint 10 (round), block 0 (BlkSeed)
        let code = vec![0x81, 10, 0xd1, 0x00];
        let raw = prog(7, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        m.step(&mut ctx).unwrap(); // pushint succeeds
        let result = m.step(&mut ctx); // block fails
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("block field access not available"),
            "got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Box storage opcode tests
    // -----------------------------------------------------------------------

    /// Helper: build pushbytes instruction for a byte slice.
    fn pushbytes_code(data: &[u8]) -> Vec<u8> {
        let mut code = vec![0x80, data.len() as u8];
        code.extend_from_slice(data);
        code
    }

    /// Helper: build pushint instruction for a small uint (< 128).
    fn pushint_code(val: u8) -> Vec<u8> {
        vec![0x81, val]
    }

    // --- box_create ---

    #[test]
    fn test_box_create_new() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "mybox", pushint 10, box_create (0xb9)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(10));
        code.push(0xb9);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1)); // newly created
        assert_eq!(ctx.boxes.get(b"mybox".as_slice()).unwrap().len(), 10);
        assert!(ctx
            .boxes
            .get(b"mybox".as_slice())
            .unwrap()
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn test_box_create_existing() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 10]);
        // pushbytes "mybox", pushint 10, box_create
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(10));
        code.push(0xb9);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // already existed
    }

    #[test]
    fn test_box_create_empty_name_rejected() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "" (length 0), pushint 10, box_create
        let mut code = vec![0x80, 0x00]; // pushbytes, len=0
        code.extend_from_slice(&pushint_code(10));
        code.push(0xb9);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap(); // pushbytes + pushint succeed
        let result = m.step(&mut ctx); // box_create fails
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("zero length"), "got: {msg}");
    }

    // --- box_del ---

    #[test]
    fn test_box_del_existing() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![1, 2, 3]);
        // pushbytes "mybox", box_del (0xbc)
        let mut code = pushbytes_code(b"mybox");
        code.push(0xbc);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1)); // existed
        assert!(!ctx.boxes.contains_key(b"mybox".as_slice()));
    }

    #[test]
    fn test_box_del_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", box_del
        let mut code = pushbytes_code(b"nobox");
        code.push(0xbc);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // did not exist
    }

    // --- box_len ---

    #[test]
    fn test_box_len_existing() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 42]);
        // pushbytes "mybox", box_len (0xbd)
        let mut code = pushbytes_code(b"mybox");
        code.push(0xbd);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(42)); // length
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // exists
    }

    #[test]
    fn test_box_len_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", box_len
        let mut code = pushbytes_code(b"nobox");
        code.push(0xbd);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(0)); // length = 0
        assert_eq!(m.stack[1], AvmValue::Uint64(0)); // does not exist
    }

    // --- box_get ---

    #[test]
    fn test_box_get_existing() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0xAA, 0xBB, 0xCC]);
        // pushbytes "mybox", box_get (0xbe)
        let mut code = pushbytes_code(b"mybox");
        code.push(0xbe);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Bytes(vec![0xAA, 0xBB, 0xCC]));
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // exists
    }

    #[test]
    fn test_box_get_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", box_get
        let mut code = pushbytes_code(b"nobox");
        code.push(0xbe);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Bytes(vec![])); // empty
        assert_eq!(m.stack[1], AvmValue::Uint64(0)); // does not exist
    }

    // --- box_put ---

    #[test]
    fn test_box_put() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "mybox", pushbytes "hello", box_put (0xbf)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushbytes_code(b"hello"));
        code.push(0xbf);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(m.stack.len(), 0);
        assert_eq!(ctx.boxes.get(b"mybox".as_slice()).unwrap(), b"hello");
    }

    #[test]
    fn test_box_put_overwrites_existing() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 5]);
        // pushbytes "mybox", pushbytes "world", box_put
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushbytes_code(b"world"));
        code.push(0xbf);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        assert_eq!(ctx.boxes.get(b"mybox".as_slice()).unwrap(), b"world");
    }

    // --- box_extract ---

    #[test]
    fn test_box_extract() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), b"hello world".to_vec());
        // pushbytes "mybox", pushint 6, pushint 5, box_extract (0xba)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(6)); // offset
        code.extend_from_slice(&pushint_code(5)); // length
        code.push(0xba);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 4).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Bytes(b"world".to_vec()));
    }

    #[test]
    fn test_box_extract_out_of_bounds() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 5]);
        // pushbytes "mybox", pushint 3, pushint 5, box_extract -> out of bounds
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(3));
        code.extend_from_slice(&pushint_code(5));
        code.push(0xba);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("beyond length"), "got: {msg}");
    }

    #[test]
    fn test_box_extract_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", pushint 0, pushint 1, box_extract -> no such box
        let mut code = pushbytes_code(b"nobox");
        code.extend_from_slice(&pushint_code(0));
        code.extend_from_slice(&pushint_code(1));
        code.push(0xba);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no such box"), "got: {msg}");
    }

    // --- box_replace ---

    #[test]
    fn test_box_replace() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), b"hello world".to_vec());
        // pushbytes "mybox", pushint 6, pushbytes "EARTH", box_replace (0xbb)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(6)); // offset
        code.extend_from_slice(&pushbytes_code(b"EARTH"));
        code.push(0xbb);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 4).unwrap();
        assert_eq!(m.stack.len(), 0);
        assert_eq!(ctx.boxes.get(b"mybox".as_slice()).unwrap(), b"hello EARTH");
    }

    #[test]
    fn test_box_replace_out_of_bounds() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 5]);
        // pushbytes "mybox", pushint 3, pushbytes "ABC", box_replace
        // offset 3 + len 3 = 6 > 5 -> error
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(3));
        code.extend_from_slice(&pushbytes_code(b"ABC"));
        code.push(0xbb);
        let raw = prog(8, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("beyond length"), "got: {msg}");
    }

    // --- box_resize ---

    #[test]
    fn test_box_resize_grow() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), b"abc".to_vec());
        // pushbytes "mybox", pushint 6, box_resize (0xd3)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(6));
        code.push(0xd3);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        let box_val = ctx.boxes.get(b"mybox".as_slice()).unwrap();
        assert_eq!(box_val.len(), 6);
        assert_eq!(&box_val[..3], b"abc");
        assert_eq!(&box_val[3..], &[0, 0, 0]); // zero-extended
    }

    #[test]
    fn test_box_resize_shrink() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), b"abcdef".to_vec());
        // pushbytes "mybox", pushint 3, box_resize
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(3));
        code.push(0xd3);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 3).unwrap();
        let box_val = ctx.boxes.get(b"mybox".as_slice()).unwrap();
        assert_eq!(box_val, b"abc");
    }

    #[test]
    fn test_box_resize_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", pushint 5, box_resize -> error
        let mut code = pushbytes_code(b"nobox");
        code.extend_from_slice(&pushint_code(5));
        code.push(0xd3);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 2).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no such box"), "got: {msg}");
    }

    // --- box_splice ---

    #[test]
    fn test_box_splice_replace_middle() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), b"abcdefgh".to_vec());
        // pushbytes "mybox", pushint 2 (start), pushint 3 (length), pushbytes "XYZ", box_splice (0xd2)
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(2)); // start
        code.extend_from_slice(&pushint_code(3)); // length to remove
        code.extend_from_slice(&pushbytes_code(b"XYZ")); // replacement
        code.push(0xd2);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 5).unwrap();
        let box_val = ctx.boxes.get(b"mybox".as_slice()).unwrap();
        // Same size as original (8 bytes): "ab" + "XYZ" + "fgh"
        assert_eq!(box_val.len(), 8);
        assert_eq!(&box_val[..2], b"ab");
        assert_eq!(&box_val[2..5], b"XYZ");
        assert_eq!(&box_val[5..8], b"fgh");
    }

    #[test]
    fn test_box_splice_non_existing() {
        let mut ctx = TestStateContext::new(100);
        // pushbytes "nobox", pushint 0, pushint 0, pushbytes "x", box_splice
        let mut code = pushbytes_code(b"nobox");
        code.extend_from_slice(&pushint_code(0));
        code.extend_from_slice(&pushint_code(0));
        code.extend_from_slice(&pushbytes_code(b"x"));
        code.push(0xd2);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 4).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("no such box"), "got: {msg}");
    }

    #[test]
    fn test_box_splice_out_of_bounds() {
        let mut ctx = TestStateContext::new(100);
        ctx.boxes.insert(b"mybox".to_vec(), vec![0u8; 5]);
        // pushbytes "mybox", pushint 3, pushint 5, pushbytes "xx", box_splice
        // start=3 + length=5 = 8 > 5 -> error
        let mut code = pushbytes_code(b"mybox");
        code.extend_from_slice(&pushint_code(3));
        code.extend_from_slice(&pushint_code(5));
        code.extend_from_slice(&pushbytes_code(b"xx"));
        code.push(0xd2);
        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        step_n(&mut m, &mut ctx, 4).unwrap();
        let result = m.step(&mut ctx);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("beyond"), "got: {msg}");
    }

    // -----------------------------------------------------------------------
    // voter_params_get tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_voter_params_get_by_index() {
        // pushint 0 (account index), voter_params_get field=0 (VoterBalance)
        let addr = test_addr(0xAA);
        let raw = prog(11, &[0x81, 0x00, 0x74, 0x00]); // pushint 0, voter_params_get 0
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.accounts.push(addr);
        ctx.voter_params
            .insert((addr, 0), (TealValue::Uint(999_000), true));
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(999_000));
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // did_exist = true
    }

    #[test]
    fn test_voter_params_get_by_address() {
        // pushbytes <32-byte addr>, voter_params_get field=0 (VoterBalance)
        let addr = test_addr(0xBB);
        let mut code = vec![0x80, 0x20]; // pushbytes, length=32
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x74, 0x00]); // voter_params_get field=0
        let raw = prog(11, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.voter_params
            .insert((addr, 0), (TealValue::Uint(500_000), true));
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(500_000));
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // did_exist = true
    }

    #[test]
    fn test_voter_params_get_not_found() {
        // pushint 0 (account index), voter_params_get field=0 — account not in voter_params
        let addr = test_addr(0xCC);
        let raw = prog(11, &[0x81, 0x00, 0x74, 0x00]); // pushint 0, voter_params_get 0
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.accounts.push(addr);
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(0));
        assert_eq!(m.stack[1], AvmValue::Uint64(0)); // did_exist = false
    }

    #[test]
    fn test_voter_params_get_incentive_eligible_by_address() {
        // pushbytes <32-byte addr>, voter_params_get field=1 (VoterIncentiveEligible)
        let addr = test_addr(0xDD);
        let mut code = vec![0x80, 0x20]; // pushbytes, length=32
        code.extend_from_slice(&addr);
        code.extend_from_slice(&[0x74, 0x01]); // voter_params_get field=1
        let raw = prog(11, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let mut ctx = TestStateContext::new(100);
        ctx.voter_params
            .insert((addr, 1), (TealValue::Uint(1), true));
        step_n(&mut m, &mut ctx, 2).unwrap();
        assert_eq!(m.stack.len(), 2);
        assert_eq!(m.stack[0], AvmValue::Uint64(1));
        assert_eq!(m.stack[1], AvmValue::Uint64(1)); // did_exist = true
    }
}
