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

//! AVM execution context -- external state access for the VM.
//!
//! The `AvmContext` trait provides all the external state that opcodes may
//! need: transaction fields, global fields, account/asset/app lookups,
//! state reads/writes, inner transactions, logging, etc.
//!
//! `NullContext` is a no-op implementation that returns errors for every
//! method, allowing pure stack/math/byte tests to run without wiring up
//! real state.

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{Address, SignedTransaction, TealValue};

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

    /// Set the `ForeignBoxReads` flag on `app_id`'s params
    /// (`app_params_set AppForeignBoxReads`). When enabled, any app may read
    /// (but not write) this app's boxes. Matches go-algorand's
    /// `LedgerForLogic.SetForeignBoxReads` (`data/transactions/logic/eval.go`).
    fn set_foreign_box_reads(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
        let _ = (app_id, enable);
        Err(AlgoError::Avm {
            message: "context unavailable: set_foreign_box_reads".into(),
        })
    }

    /// Set the `FamilyBoxAccess` flag on `app_id`'s params
    /// (`app_params_set AppFamilyBoxAccess`). When enabled, any app (existing
    /// or future) with the same creator may read and write this app's boxes.
    /// Matches go-algorand's `LedgerForLogic.SetFamilyBoxAccess`
    /// (`data/transactions/logic/eval.go`).
    fn set_family_box_access(&mut self, app_id: u64, enable: bool) -> Result<(), AlgoError> {
        let _ = (app_id, enable);
        Err(AlgoError::Avm {
            message: "context unavailable: set_family_box_access".into(),
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

    /// Read scratch slot from another transaction in the group
    /// (`gload`/`gloads`/`gloadss`). `op_name` is the calling opcode's name
    /// (`"gload"`, `"gloads"`, or `"gloadss"`), used to build error messages
    /// that match go-algorand's `opGloadImpl` (`data/transactions/logic/eval.go`).
    fn gload(&self, op_name: &str, group_index: usize, slot: u8) -> Result<TealValue, AlgoError> {
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

    /// Set the context's tracked opcode budget (for budget sharing with
    /// inner app calls). Called by `op_itxn_submit` before execution.
    fn set_opcode_budget(&mut self, _budget: i64) {}

    /// Get the context's tracked opcode budget. Called by `op_itxn_submit`
    /// after inner execution to read back the (possibly reduced) budget.
    fn get_opcode_budget(&self) -> i64 {
        0
    }

    /// Whether this context implements real budget pooling.
    ///
    /// When `true`, `op_itxn_submit` always reads back the budget from
    /// `get_opcode_budget()` after inner execution — even if the result is 0
    /// (legitimate exhaustion). When `false` (the default), `op_itxn_submit`
    /// preserves the machine's pre-submit budget so that stub contexts that
    /// return 0 from `get_opcode_budget()` don't accidentally zero the budget.
    fn supports_budget_pooling(&self) -> bool {
        false
    }

    /// `EnablePrecheckECDSACurve` (go-algorand v38+, `config/consensus.go`):
    /// the `ecdsa_verify` opcode bails early, returning `false`, if the
    /// supplied Secp256r1 public key is not on the curve, instead of
    /// (pre-fix) proceeding directly to signature verification with a
    /// possibly-invalid point. Defaults to `true` (the modern/always-fixed
    /// behavior) so stub/test contexts that don't wire consensus params get
    /// the safe, current behavior.
    fn enable_precheck_ecdsa_curve(&self) -> bool {
        true
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

    // ---- Inner transaction caller / depth ----

    /// The app ID of the application that invoked this one via inner txn.
    /// Returns 0 if this is a top-level execution (no caller).
    fn caller_app_id(&self) -> u64 {
        0
    }

    /// The application address of the caller app.
    /// Returns the zero address if this is a top-level execution.
    fn caller_app_address(&self) -> [u8; 32] {
        [0u8; 32]
    }

    /// Current inner transaction call depth.
    /// 0 for top-level app calls, incremented for each level of inner app call.
    fn inner_txn_depth(&self) -> u32 {
        0
    }

    /// Active consensus protocol's `LogicSigVersion` ceiling, if known.
    ///
    /// When `Some(v)`, the eval entry points (`run_approval_program`,
    /// `run_logicsig_program` and their tracer variants) reject programs whose
    /// declared version byte exceeds `v`. Matches go-algorand's pre-eval
    /// `proto.LogicSigVersion` check in `data/transactions/logic/eval.go`.
    ///
    /// Returns `None` for contexts that do not carry consensus params — e.g.
    /// [`NullContext`] used in unit tests. In that case the check is skipped
    /// and only the hard `MAX_AVM_VERSION` ceiling applies (enforced by the
    /// bytecode parser).
    fn consensus_logic_sig_version(&self) -> Option<u64> {
        None
    }

    /// Minimum AVM version required for the program under evaluation, given
    /// the rest of its transaction group.
    ///
    /// Matches go-algorand's `computeMinAvmVersion`
    /// (`data/transactions/logic/eval.go`): a group containing a `RekeyTo`
    /// (rekeying) transaction or an `ApplicationCall` transaction raises the
    /// minimum required AVM version for every LogicSig signature in that
    /// group, because those transaction fields/types postdate AVM v1 and
    /// older-version programs must not be exposed to groups using them.
    ///
    /// Defaults to `0` (no floor) for contexts that don't carry a
    /// transaction group — e.g. [`NullContext`] used in unit tests.
    fn min_avm_version(&self) -> u64 {
        0
    }

    /// Whether the currently-executing transaction's unified `Access`
    /// (resource-sharing) array is non-empty.
    ///
    /// Used by `run_approval_program`/`run_clear_state_program` to reject a
    /// pre-`sharedResourcesVersion` program invoked with `tx.Access` set,
    /// matching go-algorand's `(*EvalContext).begin` check
    /// (`data/transactions/logic/eval.go`):
    /// `version < sharedResourcesVersion && cx.runMode == ModeApp &&
    /// len(cx.txn.Txn.Access) > 0`.
    ///
    /// Defaults to `false` for contexts that don't carry a transaction
    /// (e.g. [`NullContext`] used in unit tests).
    fn txn_has_access(&self) -> bool {
        false
    }

    // ---- Box storage ----

    /// Get a box's contents. Returns `(value, exists)`.
    /// If the box does not exist, returns `(vec![], false)`.
    fn box_get(&mut self, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_get".into(),
        })
    }

    /// Write a value to an existing box (must already exist and size must match),
    /// or create a new box if it does not exist.
    fn box_put(&mut self, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_put".into(),
        })
    }

    /// Delete a box. Returns whether the box existed.
    fn box_del(&mut self, name: &[u8]) -> Result<bool, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_del".into(),
        })
    }

    /// Get a box's length. Returns `(length, exists)`.
    fn box_len(&mut self, name: &[u8]) -> Result<(u64, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_len".into(),
        })
    }

    /// Create a box of the given size (zero-filled). Returns `true` if newly
    /// created, `false` if the box already existed (with matching size).
    fn box_create(&mut self, name: &[u8], size: u64) -> Result<bool, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_create".into(),
        })
    }

    /// Extract a slice from a box's contents.
    fn box_extract(&mut self, name: &[u8], offset: u64, length: u64) -> Result<Vec<u8>, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_extract".into(),
        })
    }

    /// Replace bytes within a box starting at `offset`.
    fn box_replace(&mut self, name: &[u8], offset: u64, value: &[u8]) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_replace".into(),
        })
    }

    /// Resize a box, preserving existing content (truncating or zero-extending).
    fn box_resize(&mut self, name: &[u8], new_size: u64) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_resize".into(),
        })
    }

    /// Splice bytes within a box: remove `length` bytes at `start`, insert
    /// `value` in their place. The box size changes by
    /// `value.len() - length`.
    fn box_splice(
        &mut self,
        name: &[u8],
        start: u64,
        length: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: box_splice".into(),
        })
    }

    // ---- Foreign box storage (`app_box_*`, v5.0.0-stable / foreignBoxVersion) ----
    //
    // Each is the "foreign" counterpart of the like-named `box_*` method
    // above, operating on a box owned by `app_id` rather than the current
    // app. Matches go-algorand's `boxXxxImpl(cx, popDeepAppID(cx, depth))`
    // (`data/transactions/logic/box.go:311-599`): the *implementation* is
    // shared with the plain `box_*` path (both eventually authorize via
    // `authorizeBoxAccess`/`availableAppBox`); only the target app differs.
    // Accessing `app_id == current_app_id()` is always allowed, matching
    // `authorizeBoxAccess`'s "an app may always access its own boxes" rule.
    // Accessing another app's box additionally requires that app's
    // `ForeignBoxReads`/`FamilyBoxAccess` `AppParams` flags to permit it (see
    // `data/transactions/logic/box.go:42-122`).

    /// `app_box_get` (0xd4/0x06): get a box's contents. Returns `(value, exists)`.
    fn app_box_get(&mut self, app_id: u64, name: &[u8]) -> Result<(Vec<u8>, bool), AlgoError> {
        let _ = (app_id, name);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_get".into(),
        })
    }

    /// `app_box_put` (0xd4/0x07): write or create a box on `app_id`.
    fn app_box_put(&mut self, app_id: u64, name: &[u8], value: &[u8]) -> Result<(), AlgoError> {
        let _ = (app_id, name, value);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_put".into(),
        })
    }

    /// `app_box_del` (0xd4/0x04): delete a box on `app_id`. Returns whether it existed.
    fn app_box_del(&mut self, app_id: u64, name: &[u8]) -> Result<bool, AlgoError> {
        let _ = (app_id, name);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_del".into(),
        })
    }

    /// `app_box_len` (0xd4/0x05): get a box's length on `app_id`. Returns `(length, exists)`.
    fn app_box_len(&mut self, app_id: u64, name: &[u8]) -> Result<(u64, bool), AlgoError> {
        let _ = (app_id, name);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_len".into(),
        })
    }

    /// `app_box_create` (0xd4/0x01): create a box of the given size on `app_id`.
    fn app_box_create(&mut self, app_id: u64, name: &[u8], size: u64) -> Result<bool, AlgoError> {
        let _ = (app_id, name, size);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_create".into(),
        })
    }

    /// `app_box_extract` (0xd4/0x02): extract a slice from a box on `app_id`.
    fn app_box_extract(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, AlgoError> {
        let _ = (app_id, name, offset, length);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_extract".into(),
        })
    }

    /// `app_box_replace` (0xd4/0x03): replace bytes within a box on `app_id`.
    fn app_box_replace(
        &mut self,
        app_id: u64,
        name: &[u8],
        offset: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        let _ = (app_id, name, offset, value);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_replace".into(),
        })
    }

    /// `app_box_resize` (0xd4/0x09): resize a box on `app_id`.
    fn app_box_resize(&mut self, app_id: u64, name: &[u8], new_size: u64) -> Result<(), AlgoError> {
        let _ = (app_id, name, new_size);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_resize".into(),
        })
    }

    /// `app_box_splice` (0xd4/0x08): splice bytes within a box on `app_id`.
    fn app_box_splice(
        &mut self,
        app_id: u64,
        name: &[u8],
        start: u64,
        length: u64,
        value: &[u8],
    ) -> Result<(), AlgoError> {
        let _ = (app_id, name, start, length, value);
        Err(AlgoError::Avm {
            message: "context unavailable: app_box_splice".into(),
        })
    }

    // ---- Resource availability ----

    /// Check if an asset is available (in foreign arrays or created by a prior
    /// inner transaction). Used for resource availability checking.
    fn is_asset_available(&self, asset_id: u64) -> bool {
        // Default: not available. Overridden by LedgerAvmContext.
        let _ = asset_id;
        false
    }

    /// Check if an app is available (in foreign arrays, is the current app,
    /// or was created by a prior inner transaction).
    fn is_app_available(&self, app_id: u64) -> bool {
        // Default: not available. Overridden by LedgerAvmContext.
        let _ = app_id;
        false
    }

    /// Check if a raw 32-byte address (as opposed to a foreign-array index)
    /// is available under the transaction group's resource-availability
    /// rules. Matches go-algorand's `availableAccount`
    /// (`data/transactions/logic/eval.go`).
    ///
    /// Defaults to `true` (no restriction) for contexts that don't track
    /// group resources at all -- e.g. `LogicSigAvmContext`, which already
    /// rejects every account-state read via its other trait-default
    /// "context unavailable" implementations, so this default never
    /// actually grants access to anything a LogicSig context can act on.
    /// `LedgerAvmContext` overrides this with the real check.
    fn is_account_available(&self, addr: &[u8; 32]) -> bool {
        let _ = addr;
        true
    }

    /// Check if a raw 32-byte address is a *named* reference: the current
    /// transaction's own sender, or a member of its `Accounts`/`Access`
    /// array. This is the narrow subset of [`Self::is_account_available`]'s
    /// checks that go-algorand's `mutableAccountReference`
    /// (`data/transactions/logic/eval.go`) treats as always resolvable to a
    /// real `txn.Accounts` position (`IndexByAddress` succeeds), as opposed
    /// to the "available via some other path" sentinel that only becomes
    /// acceptable for a *mutating* local-state op
    /// (`app_local_put`/`app_local_del`) at `sharedResourcesVersion` (v9+).
    /// Unlike `is_account_available`, this deliberately excludes
    /// created-app addresses, foreign-apps addresses, group-shared
    /// accounts, the current app's own address, and simulation's
    /// unnamed-resource relaxation -- all of those are only valid mutation
    /// targets from v9 onward, matched by the version gate the caller
    /// applies alongside this check (`resolve_mutable_account`).
    ///
    /// Defaults to `false` (conservative — a context that doesn't track
    /// group resources at all has no sender/`Accounts` array to consult).
    /// `LedgerAvmContext` overrides this with the real check.
    fn is_named_account(&self, addr: &[u8; 32]) -> bool {
        let _ = addr;
        false
    }

    /// Check if an asset holding (account+asset cross-product) is available
    /// under the transaction group's resource-sharing rules (AVM v9+,
    /// `sharedResourcesVersion`). Matches go-algorand's `allowsHolding`
    /// (`data/transactions/logic/resources.go`).
    ///
    /// Defaults to `true` (no restriction), matching
    /// [`Self::is_account_available`]'s rationale: contexts that don't
    /// track group resources at all don't restrict. Callers must
    /// independently gate on the AVM version before consulting this --
    /// `LedgerAvmContext` overrides it with the real cross-product check.
    fn is_holding_available(&self, addr: &[u8; 32], asset_id: u64) -> bool {
        let _ = (addr, asset_id);
        true
    }

    /// Check if an app local state (account+app cross-product) is
    /// available. Matches go-algorand's `allowsLocals`. See
    /// [`Self::is_holding_available`] for the shared rationale.
    fn is_local_available(&self, addr: &[u8; 32], app_id: u64) -> bool {
        let _ = (addr, app_id);
        true
    }

    // ---- Voter / stake queries ----

    /// Get voter parameters for an account (from balance round, 320 rounds back).
    /// Returns `(value, did_exist)` where `did_exist` is true if the account was
    /// online at the balance round.
    fn voter_params_get(
        &self,
        account: &[u8; 32],
        field: u8,
    ) -> Result<(TealValue, bool), AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: voter_params_get".into(),
        })
    }

    /// Get the total online stake in microAlgos (from the balance round).
    fn online_stake(&self) -> Result<u64, AlgoError> {
        Err(AlgoError::Avm {
            message: "context unavailable: online_stake".into(),
        })
    }

    // ---- Result extraction ----
    //
    // These methods allow `eval.rs` to extract accumulated execution results
    // (logs, inner transactions, state deltas) from the context after program
    // execution, without needing to know the concrete context type.
    //
    // Default implementations return empty collections, which is correct for
    // `NullContext` and LogicSig mode. `LedgerAvmContext` overrides these to
    // drain its accumulated state.

    /// Take accumulated log entries, leaving the context's log list empty.
    fn take_logs(&mut self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Take accumulated inner transactions (flattened), leaving the context empty.
    fn take_inner_transactions(&mut self) -> Vec<SignedTransaction> {
        Vec::new()
    }

    /// Take accumulated global state delta, leaving the context empty.
    /// `Some(val)` = set, `None` = delete.
    fn take_global_delta(&mut self) -> HashMap<Vec<u8>, Option<TealValue>> {
        HashMap::new()
    }

    /// Take accumulated local state deltas, leaving the context empty.
    /// Inner values: `Some(val)` = set, `None` = delete.
    fn take_local_deltas(&mut self) -> HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>> {
        HashMap::new()
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
        assert_eq!(ctx.caller_app_id(), 0);
        assert_eq!(ctx.caller_app_address(), [0u8; 32]);
        assert_eq!(ctx.inner_txn_depth(), 0);
    }
}
