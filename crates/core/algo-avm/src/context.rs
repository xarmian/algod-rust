//! AVM execution context -- external state access for the VM.
//!
//! The `AvmContext` trait provides all the external state that opcodes may
//! need: transaction fields, global fields, account/asset/app lookups,
//! state reads/writes, inner transactions, logging, etc.
//!
//! `NullContext` is a no-op implementation that returns errors for every
//! method, allowing pure stack/math/byte tests to run without wiring up
//! real state.

use algo_error::AlgoError;
use algo_types::TealValue;

use crate::machine::AvmValue;

/// Trait providing external state access to the AVM.
///
/// Passed as `&mut dyn AvmContext` to `step()` / `run()` so the machine
/// itself remains lifetime- and generic-free.
///
/// All methods have default implementations that return an error or a
/// zero/false value so that test mocks only need to override the methods
/// they actually use.
#[allow(unused_variables)]
pub trait AvmContext {
    // ---- Transaction access ----

    /// Get a transaction field value.  `group_index` selects the txn within
    /// the group; `field` is the raw field byte (mapped by the opcode handler
    /// to a TxnField enum); `array_index` is used for array-typed fields.
    fn txn_field(
        &self,
        group_index: usize,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: txn_field".into(),
        })
    }

    /// Number of transactions in the current group.
    fn group_size(&self) -> usize {
        0
    }

    /// Index of the current transaction within its group.
    fn group_index(&self) -> usize {
        0
    }

    // ---- Global fields ----

    /// Get a global field value by raw field byte.
    fn global_field(&self, field: u8) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: global_field".into(),
        })
    }

    // ---- LogicSig arguments ----

    /// Get LogicSig argument at `index`.
    fn arg(&self, index: usize) -> Result<Vec<u8>, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: arg".into(),
        })
    }

    /// Number of LogicSig arguments.
    fn num_args(&self) -> usize {
        0
    }

    // ---- Account / asset / app reference resolution ----

    /// Resolve an `apat` (accounts) array index to an address.
    /// Index 0 = sender.
    fn resolve_account(&self, index: u64) -> Result<[u8; 32], AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: resolve_account".into(),
        })
    }

    /// Resolve an `apas` (foreign assets) array index to an asset ID.
    fn resolve_asset(&self, index: u64) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: resolve_asset".into(),
        })
    }

    /// Resolve an `apfa` (foreign apps) array index to an app ID.
    /// Index 0 = current app.
    fn resolve_app(&self, index: u64) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: resolve_app".into(),
        })
    }

    // ---- State reads ----

    /// Check whether `account` has opted in to `app_id`.
    fn app_opted_in(&self, account: &[u8; 32], app_id: u64) -> Result<bool, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_opted_in".into(),
        })
    }

    /// Read a key from an app's local state for `account`.
    fn app_local_get(
        &self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<Option<TealValue>, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_local_get".into(),
        })
    }

    /// Read a key from an app's global state.
    fn app_global_get(&self, app_id: u64, key: &[u8]) -> Result<Option<TealValue>, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_global_get".into(),
        })
    }

    // ---- State writes ----

    /// Write a key/value to an app's local state for `account`.
    fn app_local_put(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_local_put".into(),
        })
    }

    /// Delete a key from an app's local state for `account`.
    fn app_local_del(
        &mut self,
        account: &[u8; 32],
        app_id: u64,
        key: &[u8],
    ) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_local_del".into(),
        })
    }

    /// Write a key/value to an app's global state.
    fn app_global_put(
        &mut self,
        app_id: u64,
        key: &[u8],
        value: TealValue,
    ) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_global_put".into(),
        })
    }

    /// Delete a key from an app's global state.
    fn app_global_del(&mut self, app_id: u64, key: &[u8]) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_global_del".into(),
        })
    }

    // ---- Account / asset / app parameter queries ----

    /// Account balance in microAlgos.
    fn balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: balance".into(),
        })
    }

    /// Minimum balance for `account`.
    fn min_balance(&self, account: &[u8; 32]) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: min_balance".into(),
        })
    }

    /// Get an asset holding field. Returns `(value, exists)`.
    fn asset_holding_get(
        &self,
        account: &[u8; 32],
        asset_id: u64,
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: asset_holding_get".into(),
        })
    }

    /// Get an asset params field. Returns `(value, exists)`.
    fn asset_params_get(&self, asset_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: asset_params_get".into(),
        })
    }

    /// Get an app params field. Returns `(value, exists)`.
    fn app_params_get(&self, app_id: u64, field: u8) -> Result<(TealValue, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: app_params_get".into(),
        })
    }

    /// Get an account params field. Returns `(value, exists)`.
    fn acct_params_get(
        &self,
        account: &[u8; 32],
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: acct_params_get".into(),
        })
    }

    // ---- Logging ----

    /// Append a log message.
    fn log(&mut self, data: Vec<u8>) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: log".into(),
        })
    }

    // ---- Group scratch space ----

    /// Read scratch slot from another transaction in the group (`gload`/`gloads`).
    fn gload(&self, group_index: usize, slot: u8) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: gload".into(),
        })
    }

    // ---- Group created IDs (gaid/gaids) ----

    /// Get the created asset or app ID from a prior transaction in the group.
    /// Used by `gaid` (0x3c) and `gaids` (0x3d).
    fn created_id(&self, group_index: usize) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: created_id".into(),
        })
    }

    // ---- Block field access ----

    /// Get a field from a past block header.
    /// Used by `block` (0xd1).
    /// `field` values: 0=BlkSeed, 1=BlkTimestamp, etc.
    fn block_field(&self, round: u64, field: u8) -> Result<AvmValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: block_field".into(),
        })
    }

    // ---- Inner transactions ----

    /// Begin building an inner transaction.
    fn itxn_begin(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: itxn_begin".into(),
        })
    }

    /// Set a field on the inner transaction being built.
    fn itxn_field(&mut self, field: u8, value: TealValue) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: itxn_field".into(),
        })
    }

    /// Finish the current inner transaction and begin the next one in a group.
    fn itxn_next(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: itxn_next".into(),
        })
    }

    /// Submit the inner transaction (group).
    fn itxn_submit(&mut self) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: itxn_submit".into(),
        })
    }

    /// Read a field from the last submitted inner transaction.
    fn last_itxn_field(
        &self,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: last_itxn_field".into(),
        })
    }

    /// Read a field from a specific inner transaction within the last submitted group.
    fn last_itxn_group_field(
        &self,
        group_index: usize,
        field: u8,
        array_index: Option<usize>,
    ) -> Result<TealValue, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: last_itxn_group_field".into(),
        })
    }

    /// Number of inner transactions submitted so far.
    fn num_inner_txns(&self) -> usize {
        0
    }

    // ---- Execution mode / identity ----

    /// `true` for application calls, `false` for LogicSig.
    fn is_app_mode(&self) -> bool {
        false
    }

    /// The ID of the application currently being executed.
    fn current_app_id(&self) -> u64 {
        0
    }

    /// SHA-512/256 hash of the program bytes (for ed25519verify domain separation).
    fn program_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

// ---------------------------------------------------------------------------
// NullContext -- stub for pure-opcode tests
// ---------------------------------------------------------------------------

/// A no-op context that returns `AlgoError::Avm` with a "context unavailable"
/// message for every method. Useful for unit tests that only exercise pure
/// stack / math / byte / flow opcodes and never touch external state.
pub struct NullContext;

impl AvmContext for NullContext {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_context_txn_field_returns_error() {
        let ctx = NullContext;
        let result = ctx.txn_field(0, 0, None);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("context unavailable"), "got: {msg}");
    }

    #[test]
    fn null_context_trivial_getters() {
        let ctx = NullContext;
        assert_eq!(ctx.group_size(), 0);
        assert_eq!(ctx.group_index(), 0);
        assert_eq!(ctx.num_args(), 0);
        assert_eq!(ctx.num_inner_txns(), 0);
        assert!(!ctx.is_app_mode());
        assert_eq!(ctx.current_app_id(), 0);
        assert_eq!(ctx.program_hash(), [0u8; 32]);
    }
}
