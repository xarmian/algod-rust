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

use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{
    Address, AppLocalState, AppParams, SignedTransaction, StateSchema, TealValue, Transaction,
};

use crate::apply::{apply_transaction, ApplyContext};

// NOTE: LedgerStore is referenced via full path in function bounds rather
// than imported at module level. See apply.rs for rationale.

// The wire/REST numbers of go-algorand's `basics.DeltaAction`
// (`data/basics/teal.go` lines 30-37: `SetBytesAction = 1`,
// `SetUintAction = 2`, `DeleteAction = 3`). This is the single place the
// numbers are defined: the enum discriminants, `From<DeltaAction> for u64`
// (used by `encode_eval_delta`) and `TryFrom<u64>` all derive from these.
const SET_BYTES_ACTION: u64 = 1;
const SET_UINT_ACTION: u64 = 2;
const DELETE_ACTION: u64 = 3;

/// Action types for state delta changes.
///
/// Numbering matches go-algorand's `basics.DeltaAction`
/// (`data/basics/teal.go`): `SetBytesAction = 1`, `SetUintAction = 2`,
/// `DeleteAction = 3`. This is the `at` field on the wire and `action` in
/// the REST JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DeltaAction {
    SetBytes = SET_BYTES_ACTION,
    SetUint = SET_UINT_ACTION,
    Delete = DELETE_ACTION,
}

impl From<DeltaAction> for u64 {
    fn from(a: DeltaAction) -> u64 {
        match a {
            DeltaAction::SetBytes => SET_BYTES_ACTION,
            DeltaAction::SetUint => SET_UINT_ACTION,
            DeltaAction::Delete => DELETE_ACTION,
        }
    }
}

impl TryFrom<u64> for DeltaAction {
    type Error = AlgoError;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            SET_BYTES_ACTION => Ok(DeltaAction::SetBytes),
            SET_UINT_ACTION => Ok(DeltaAction::SetUint),
            DELETE_ACTION => Ok(DeltaAction::Delete),
            _ => Err(AlgoError::Ledger {
                message: format!("invalid DeltaAction: {}", v),
            }),
        }
    }
}

/// A single key-value state change.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueDelta {
    pub action: DeltaAction,
    pub uint: u64,
    pub bytes: Vec<u8>,
}

/// Typed representation of an EvalDelta (ApplyData.dt field).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvalDelta {
    /// Global state changes keyed by state key.
    pub global_delta: Option<HashMap<Vec<u8>, ValueDelta>>,
    /// Per-account local state changes. Outer key is the account index into the
    /// wire layout `[sender, accounts..., shared_accts...]`, inner key is state
    /// key. Indices past the transaction's Accounts array address into
    /// [`shared_accts`](Self::shared_accts).
    pub local_deltas: Option<HashMap<u64, HashMap<Vec<u8>, ValueDelta>>>,
    /// Inner transactions (each with their own ApplyData/EvalDelta).
    pub inner_txns: Option<Vec<SignedTransaction>>,
    /// Log messages emitted by the application.
    pub logs: Option<Vec<Vec<u8>>>,
    /// Shared accounts (`sa`): addresses for local-delta indices that fall past
    /// the transaction's Accounts array (cross-transaction resource sharing).
    /// Indexed after `accounts`: wire index `1 + accounts.len() + i` resolves to
    /// `shared_accts[i]`. Matches go-algorand `EvalDelta.SharedAccts`.
    pub shared_accts: Option<Vec<Address>>,
}

/// Parse an EvalDelta from an rmpv::Value (the `dt` field on SignedTransaction).
///
/// The rmpv::Value is expected to be a Map with string keys:
/// - "gd": global delta (map of string key -> ValueDelta map)
/// - "ld": local deltas (map of uint index -> map of string key -> ValueDelta map)
/// - "itx": inner transactions (array of msgpack-encoded SignedTransaction)
/// - "lg": logs (array of binary/string values)
/// - "sa": shared accounts (array of 32-byte addresses) for local-delta indices
///   that fall past the transaction's Accounts array
pub fn parse_eval_delta(val: &rmpv::Value) -> Result<EvalDelta, AlgoError> {
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("eval_delta: expected map, got {:?}", val),
            });
        }
    };

    let mut global_delta = None;
    let mut local_deltas = None;
    let mut inner_txns = None;
    let mut logs = None;
    let mut shared_accts = None;

    for (k, v) in map {
        let key = value_as_str(k)?;
        match key {
            "gd" => {
                if !is_empty_value(v) {
                    global_delta = Some(parse_state_delta(v)?);
                }
            }
            "ld" => {
                if !is_empty_value(v) {
                    local_deltas = Some(parse_local_deltas(v)?);
                }
            }
            "itx" => {
                if !is_empty_value(v) {
                    inner_txns = Some(parse_inner_txns(v)?);
                }
            }
            "lg" => {
                if !is_empty_value(v) {
                    logs = Some(parse_logs(v)?);
                }
            }
            "sa" if !is_empty_value(v) => {
                shared_accts = Some(parse_shared_accts(v)?);
            }
            _ => {
                // Ignore unknown fields for forward compatibility.
            }
        }
    }

    Ok(EvalDelta {
        global_delta,
        local_deltas,
        inner_txns,
        logs,
        shared_accts,
    })
}

/// Encode an AVM execution result into the `dt` (EvalDelta) wire form
/// (`rmpv::Value`) that [`parse_eval_delta`] consumes and the REST layer renders
/// — the inverse of `parse_eval_delta`.
///
/// Used in Execute mode (e.g. the dev-mode producer) to surface state changes,
/// logs, and inner transactions on confirmation, since the AVM produces an
/// [`algo_avm::eval::AvmResult`] rather than a recorded `dt` field. Local-state
/// deltas are keyed by the account's index in the transaction (sender = 0,
/// `accounts[i]` = i+1), matching the wire format. Returns `None` when there is
/// nothing to report (no state changes, logs, or inner transactions).
///
/// Also used to build each inner app call's `dt` field during inner-transaction
/// execution (see `execute_inner_appl`), so nested `itx[*].dt` carry complete
/// global/local state deltas, logs, and their own nested inner transactions —
/// the recursion composes because each inner `SignedTransaction` already has its
/// delta encoded before the parent serializes it under `itx`.
///
/// `no_empty_local_deltas` mirrors go-algorand's `ConsensusParams.
/// NoEmptyLocalDeltas` (v27+, `config/consensus.go`): when true, an address
/// whose local-state delta map is empty (e.g. an `ApplicationOptIn` call
/// that writes no local-state key) is omitted from the `"ld"` map entirely,
/// rather than being recorded as a real empty entry. Pass the calling
/// transaction's active `ConsensusParams::no_empty_local_deltas`.
pub fn encode_eval_delta(
    result: &algo_avm::eval::AvmResult,
    txn: &Transaction,
    no_empty_local_deltas: bool,
) -> Option<rmpv::Value> {
    use rmpv::Value;

    // go writes `string` fields with msgpack str (`msgp.AppendString`), and
    // the bytes may be non-UTF-8: build the str via the wire so rmpv keeps
    // the raw bytes (`Utf8String`'s invalid-UTF-8 variant).
    fn raw_str(b: &[u8]) -> Value {
        if let Ok(s) = std::str::from_utf8(b) {
            return Value::from(s);
        }
        let mut buf = Vec::with_capacity(b.len() + 5);
        rmp::encode::write_str_len(&mut buf, b.len() as u32).expect("vec write");
        buf.extend_from_slice(b);
        rmpv::decode::read_value(&mut &buf[..]).expect("well-formed str")
    }

    // A single key→value change, go `basics.ValueDelta`
    // (`codec:",omitempty"`): `at` always (never 0), `bs` only if non-empty,
    // `ui` only if non-zero; fields in codec-name order (at, bs, ui).
    fn value_delta(v: &Option<TealValue>) -> Value {
        let at = |a: DeltaAction| (Value::from("at"), Value::from(u64::from(a)));
        match v {
            Some(TealValue::Uint(u)) => {
                let mut m = vec![at(DeltaAction::SetUint)];
                if *u != 0 {
                    m.push((Value::from("ui"), Value::from(*u)));
                }
                Value::Map(m)
            }
            Some(TealValue::Bytes(b)) => {
                let mut m = vec![at(DeltaAction::SetBytes)];
                if !b.is_empty() {
                    m.push((Value::from("bs"), raw_str(b)));
                }
                Value::Map(m)
            }
            None => Value::Map(vec![at(DeltaAction::Delete)]),
        }
    }

    // A state-delta map (go `basics.StateDelta`, `map[string]ValueDelta`):
    // str keys, sorted bytewise (go `SortString`).
    fn state_delta(m: &HashMap<Vec<u8>, Option<TealValue>>) -> Value {
        let mut items: Vec<_> = m.iter().collect();
        items.sort_by(|a, b| a.0.cmp(b.0));
        Value::Map(
            items
                .into_iter()
                .map(|(k, v)| (raw_str(k), value_delta(v)))
                .collect(),
        )
    }

    let mut entries: Vec<(Value, Value)> = Vec::new();

    if !result.global_delta.is_empty() {
        entries.push((Value::from("gd"), state_delta(&result.global_delta)));
    }

    if !result.local_deltas.is_empty() {
        // Local deltas are keyed by the account's position in the wire layout
        // [sender, accounts..., shared_accts...] (go's teal.go): sender = 0,
        // accounts[i] = i+1, and any account addressed by raw value (not in the
        // Accounts array) goes into the `sa` shared-accounts list, indexed after
        // accounts. Iterate in a deterministic order since HashMap order is
        // unspecified.
        let accounts: &[Address] = txn.accounts.as_deref().unwrap_or(&[]);
        // NoEmptyLocalDeltas (v27+, issue #1280): drop an address whose
        // per-key delta map is empty before it ever reaches the wire —
        // mirrors go's `buildEvalDelta`'s `if !noEmptyDeltas || len(d) != 0`
        // guard (`ledger/eval/appcow.go`). Pre-v27 (`no_empty_local_deltas`
        // false), an opt-in-only touch's empty map is kept as a real entry.
        let mut items: Vec<_> = result
            .local_deltas
            .iter()
            .filter(|(_, kv)| !no_empty_local_deltas || !kv.is_empty())
            .collect();
        items.sort_by_key(|(addr, _)| addr.0);
        // `sa` is appended in first-creation order (go `ensureLocalDelta`);
        // stable sort keeps address order for any address the AVM did not
        // report an order for.
        items.sort_by_key(|(addr, _)| {
            result
                .local_delta_order
                .iter()
                .position(|a| a == *addr)
                .unwrap_or(usize::MAX)
        });

        if !items.is_empty() {
            let mut shared: Vec<Address> = Vec::new();
            let mut ld: Vec<(Value, Value)> = Vec::with_capacity(items.len());
            for (addr, kv) in items {
                let index = if *addr == txn.sender {
                    0u64
                } else if let Some(i) = accounts.iter().position(|a| a == addr) {
                    (i + 1) as u64
                } else {
                    let pos = shared.iter().position(|a| a == addr).unwrap_or_else(|| {
                        shared.push(*addr);
                        shared.len() - 1
                    });
                    (1 + accounts.len() + pos) as u64
                };
                ld.push((Value::from(index), state_delta(kv)));
            }
            // go sorts the `map[uint64]StateDelta` keys ascending.
            ld.sort_by_key(|(k, _)| k.as_u64());
            entries.push((Value::from("ld"), Value::Map(ld)));
            if !shared.is_empty() {
                // `sa`: addresses for the local deltas that index beyond `accounts`.
                entries.push((
                    Value::from("sa"),
                    Value::Array(shared.iter().map(|a| Value::Binary(a.0.to_vec())).collect()),
                ));
            }
        }
    }

    if !result.inner_transactions.is_empty() {
        // Each inner transaction is go's canonical `SignedTxnWithAD`
        // (`EvalDelta.InnerTxns`), produced by the canonical encoder (sorted
        // omitempty fields, nested `dt` written str-preserving) and read back
        // with rmpv, whose decoder keeps non-UTF-8 `str` bytes. This replaces
        // the serde named-struct encoding (issue #1739).
        let itx: Vec<Value> = result
            .inner_transactions
            .iter()
            .filter_map(|stx| {
                let bytes = algo_codec::canonical_encode_signed_txn_with_ad(stx);
                rmpv::decode::read_value(&mut &bytes[..]).ok()
            })
            .collect();
        if !itx.is_empty() {
            entries.push((Value::from("itx"), Value::Array(itx)));
        }
    }

    if !result.logs.is_empty() {
        let lg: Vec<Value> = result.logs.iter().map(|l| raw_str(l)).collect();
        entries.push((Value::from("lg"), Value::Array(lg)));
    }

    if entries.is_empty() {
        None
    } else {
        // go's generated `EvalDelta.MarshalMsg` emits fields in codec-name
        // order: gd, itx, ld, lg, sa.
        entries.sort_by(|a, b| a.0.as_str().cmp(&b.0.as_str()));
        Some(Value::Map(entries))
    }
}

/// Maximum inner transaction recursion depth.
const MAX_INNER_TXN_DEPTH: u32 = 256;

/// Apply a parsed EvalDelta to the ledger state.
///
/// Updates global state, local state, and recursively applies inner transactions.
pub fn apply_eval_delta<L: crate::store_trait::LedgerStore>(
    stx: &SignedTransaction,
    delta: &EvalDelta,
    store: &mut L,
    ctx: &ApplyContext,
    depth: u32,
) -> Result<(), AlgoError> {
    let txn = &stx.txn;

    // Determine the app ID: for creates, use apply_data_application_id (apid on SignedTxn);
    // otherwise use the transaction's application_id.
    let app_id = if stx.apply_data_application_id != 0 {
        stx.apply_data_application_id
    } else {
        txn.application_id
    };

    // Apply global delta.
    if let Some(ref gd) = delta.global_delta {
        if app_id != 0 {
            // Ensure app_params entry exists.
            let mut app = store.get_or_insert_app_params(app_id, || AppParams {
                creator: txn.sender,
                approval_program: Vec::new(),
                clear_state_program: Vec::new(),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            });

            for (key, vd) in gd {
                match vd.action {
                    DeltaAction::SetUint => {
                        app.global_state
                            .insert(key.clone(), TealValue::Uint(vd.uint));
                    }
                    DeltaAction::SetBytes => {
                        app.global_state
                            .insert(key.clone(), TealValue::Bytes(vd.bytes.clone()));
                    }
                    DeltaAction::Delete => {
                        app.global_state.remove(key);
                    }
                }
            }

            store.set_app_params(app_id, app);
        }
    }

    // Apply local deltas.
    if let Some(ref ld) = delta.local_deltas {
        if app_id != 0 {
            for (&account_index, kv_deltas) in ld {
                // Resolve account address against the wire layout
                // [sender, accounts..., shared_accts...]: index 0 = sender,
                // 1..=accounts.len() = accounts[index-1], and indices past that
                // address into the `sa` shared-accounts list (cross-transaction
                // resource sharing). Mirrors go-algorand `edIndexToAddress`.
                let addr = if account_index == 0 {
                    txn.sender
                } else {
                    let accounts = txn.accounts.as_deref().unwrap_or(&[]);
                    let idx = (account_index - 1) as usize;
                    if idx < accounts.len() {
                        accounts[idx]
                    } else {
                        let shared = delta.shared_accts.as_deref().unwrap_or(&[]);
                        let shared_idx = idx - accounts.len();
                        *shared.get(shared_idx).ok_or_else(|| AlgoError::Ledger {
                            message: format!(
                                "eval_delta local: account index {} out of bounds \
                                 (accounts len {}, shared len {})",
                                account_index,
                                accounts.len(),
                                shared.len()
                            ),
                        })?
                    }
                };

                // Get or create local state entry. For recorded block replay,
                // the account should already be opted in. If not (e.g. opt-in
                // happened in an inner txn earlier in this call), create a
                // placeholder — the OptIn branch in apply_appl will fix up
                // the schema and counter afterward.
                let mut local =
                    store.get_or_insert_app_local_state(&addr, app_id, || AppLocalState {
                        schema: StateSchema::default(),
                        key_value: std::collections::BTreeMap::new(),
                    });

                for (key, vd) in kv_deltas {
                    match vd.action {
                        DeltaAction::SetUint => {
                            local
                                .key_value
                                .insert(key.clone(), TealValue::Uint(vd.uint));
                        }
                        DeltaAction::SetBytes => {
                            local
                                .key_value
                                .insert(key.clone(), TealValue::Bytes(vd.bytes.clone()));
                        }
                        DeltaAction::Delete => {
                            local.key_value.remove(key);
                        }
                    }
                }

                store.set_app_local_state(&addr, app_id, local);
            }
        }
    }

    // Recursively apply inner transactions.
    // NOTE: Inner txn recipients are not in the outer transaction's snapshot,
    // so if the outer call fails after inner txns execute, those side-effects
    // won't roll back. This is acceptable for committed block replay (blocks
    // are valid by definition). For independent validation, inner txn addresses
    // would need to be collected and added to the outer snapshot.
    if let Some(ref inner_txns) = delta.inner_txns {
        if depth >= MAX_INNER_TXN_DEPTH {
            return Err(AlgoError::Ledger {
                message: format!(
                    "inner transaction depth {} exceeds maximum {}",
                    depth, MAX_INNER_TXN_DEPTH
                ),
            });
        }
        for inner_stx in inner_txns {
            apply_transaction(store, inner_stx, ctx, depth + 1)?;
        }
    }

    Ok(())
}

/// Parse a state delta map: map of key -> ValueDelta.
fn parse_state_delta(val: &rmpv::Value) -> Result<HashMap<Vec<u8>, ValueDelta>, AlgoError> {
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("state_delta: expected map, got {:?}", val),
            });
        }
    };

    let mut result = HashMap::new();
    for (k, v) in map {
        let key_bytes = value_as_bytes(k)?;
        let vd = parse_value_delta(v)?;
        result.insert(key_bytes, vd);
    }
    Ok(result)
}

/// Parse a ValueDelta from a map with keys "at", "ui", "bs".
fn parse_value_delta(val: &rmpv::Value) -> Result<ValueDelta, AlgoError> {
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("value_delta: expected map, got {:?}", val),
            });
        }
    };

    let mut action: u64 = 0;
    let mut uint: u64 = 0;
    let mut bytes: Vec<u8> = Vec::new();

    for (k, v) in map {
        let key = value_as_str(k)?;
        match key {
            "at" => {
                action = value_as_u64(v)?;
            }
            "ui" => {
                uint = value_as_u64(v)?;
            }
            "bs" => {
                bytes = value_as_bytes(v)?;
            }
            _ => {}
        }
    }

    Ok(ValueDelta {
        action: DeltaAction::try_from(action)?,
        uint,
        bytes,
    })
}

/// Parse local deltas: map of account index (u64) -> state delta.
fn parse_local_deltas(
    val: &rmpv::Value,
) -> Result<HashMap<u64, HashMap<Vec<u8>, ValueDelta>>, AlgoError> {
    let map = match val {
        rmpv::Value::Map(m) => m,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("local_deltas: expected map, got {:?}", val),
            });
        }
    };

    let mut result = HashMap::new();
    for (k, v) in map {
        let index = value_as_u64(k)?;
        let delta = parse_state_delta(v)?;
        result.insert(index, delta);
    }
    Ok(result)
}

/// Parse inner transactions by deserializing each rmpv::Value into SignedTransaction
/// via msgpack round-trip.
fn parse_inner_txns(val: &rmpv::Value) -> Result<Vec<SignedTransaction>, AlgoError> {
    let arr = match val {
        rmpv::Value::Array(a) => a,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("inner_txns: expected array, got {:?}", val),
            });
        }
    };

    let mut txns = Vec::with_capacity(arr.len());
    for item in arr {
        txns.push(parse_inner_txn(item)?);
    }
    Ok(txns)
}

/// Parse one `itx` entry (go `SignedTxnWithAD`). Accepts go's canonical
/// omitempty form (e.g. no `txn` for an all-zero transaction) as well as the
/// legacy serde named-struct form. The entry's own `dt` is detached before
/// the serde decode and re-attached untouched: serde would turn a non-UTF-8
/// `str` into `bin`, losing go's typing for the nested delta.
fn parse_inner_txn(item: &rmpv::Value) -> Result<SignedTransaction, AlgoError> {
    let mut item = item.clone();
    let mut dt = None;
    if let rmpv::Value::Map(fields) = &mut item {
        if let Some(pos) = fields.iter().position(|(k, _)| k.as_str() == Some("dt")) {
            let (_, v) = fields.remove(pos);
            if !matches!(v, rmpv::Value::Nil) {
                dt = Some(v);
            }
        }
    }
    let mut msgpack_bytes = Vec::new();
    algo_codec::write_value_str_preserving(&mut msgpack_bytes, &item).map_err(|e| {
        AlgoError::Codec {
            source: Box::new(e),
            context: "inner_txn: failed to encode rmpv to msgpack".to_string(),
        }
    })?;
    let mut stx: SignedTransaction =
        rmp_serde::from_slice(&msgpack_bytes).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "inner_txn: failed to decode SignedTransaction".to_string(),
        })?;
    if dt.is_some() {
        stx.eval_delta = dt;
    }
    Ok(stx)
}

/// Parse shared accounts: array of 32-byte addresses (the `sa` key).
fn parse_shared_accts(val: &rmpv::Value) -> Result<Vec<Address>, AlgoError> {
    let arr = match val {
        rmpv::Value::Array(a) => a,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("shared_accts: expected array, got {:?}", val),
            });
        }
    };

    let mut result = Vec::with_capacity(arr.len());
    for item in arr {
        let bytes = value_as_bytes(item)?;
        if bytes.len() != 32 {
            return Err(AlgoError::Ledger {
                message: format!(
                    "shared_accts: expected 32-byte address, got {}",
                    bytes.len()
                ),
            });
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        result.push(Address(addr));
    }
    Ok(result)
}

/// Parse logs array.
fn parse_logs(val: &rmpv::Value) -> Result<Vec<Vec<u8>>, AlgoError> {
    let arr = match val {
        rmpv::Value::Array(a) => a,
        _ => {
            return Err(AlgoError::Ledger {
                message: format!("logs: expected array, got {:?}", val),
            });
        }
    };

    let mut result = Vec::with_capacity(arr.len());
    for item in arr {
        result.push(value_as_bytes(item)?);
    }
    Ok(result)
}

// Helper: extract a string reference from an rmpv::Value.
fn value_as_str(val: &rmpv::Value) -> Result<&str, AlgoError> {
    match val {
        rmpv::Value::String(s) => s.as_str().ok_or_else(|| AlgoError::Ledger {
            message: "invalid UTF-8 in map key".to_string(),
        }),
        _ => Err(AlgoError::Ledger {
            message: format!("expected string key, got {:?}", val),
        }),
    }
}

// Helper: extract a u64 from an rmpv::Value (handles both positive integers and signed).
fn value_as_u64(val: &rmpv::Value) -> Result<u64, AlgoError> {
    match val {
        rmpv::Value::Integer(i) => i.as_u64().ok_or_else(|| AlgoError::Ledger {
            message: format!("integer out of u64 range: {:?}", i),
        }),
        _ => Err(AlgoError::Ledger {
            message: format!("expected integer, got {:?}", val),
        }),
    }
}

// Helper: extract bytes from an rmpv::Value (handles Binary and String).
fn value_as_bytes(val: &rmpv::Value) -> Result<Vec<u8>, AlgoError> {
    match val {
        rmpv::Value::Binary(b) => Ok(b.clone()),
        rmpv::Value::String(s) => Ok(s.as_bytes().to_vec()),
        _ => Err(AlgoError::Ledger {
            message: format!("expected binary or string, got {:?}", val),
        }),
    }
}

// Helper: check if an rmpv::Value is "empty" (nil, empty map, or empty array).
fn is_empty_value(val: &rmpv::Value) -> bool {
    match val {
        rmpv::Value::Nil => true,
        rmpv::Value::Map(m) => m.is_empty(),
        rmpv::Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmpv::Value;

    /// Issue #1698: go-algorand numbers the actions `SetBytesAction = 1`,
    /// `SetUintAction = 2`, `DeleteAction = 3` (`data/basics/teal.go`).
    #[test]
    fn delta_action_numbers_match_go() {
        assert_eq!(u64::from(DeltaAction::SetBytes), 1);
        assert_eq!(u64::from(DeltaAction::SetUint), 2);
        assert_eq!(u64::from(DeltaAction::Delete), 3);
        assert_eq!(DeltaAction::try_from(1).unwrap(), DeltaAction::SetBytes);
        assert_eq!(DeltaAction::try_from(2).unwrap(), DeltaAction::SetUint);
        assert_eq!(DeltaAction::try_from(3).unwrap(), DeltaAction::Delete);
    }

    /// Decode a go-style EvalDelta (`at=1`+`bs`, `at=2`+`ui`, `at=3`).
    #[test]
    fn parse_go_numbered_eval_delta() {
        let vd = |pairs: Vec<(&str, Value)>| {
            Value::Map(
                pairs
                    .into_iter()
                    .map(|(k, v)| (Value::from(k), v))
                    .collect(),
            )
        };
        let val = Value::Map(vec![(
            Value::from("gd"),
            Value::Map(vec![
                (
                    Value::Binary(b"b".to_vec()),
                    vd(vec![
                        ("at", 1.into()),
                        ("bs", Value::Binary(b"xy".to_vec())),
                    ]),
                ),
                (
                    Value::Binary(b"u".to_vec()),
                    vd(vec![("at", 2.into()), ("ui", 7.into())]),
                ),
                (Value::Binary(b"d".to_vec()), vd(vec![("at", 3.into())])),
            ]),
        )]);
        let gd = parse_eval_delta(&val).unwrap().global_delta.unwrap();
        let b = &gd[b"b".as_slice()];
        assert_eq!(
            (b.action, b.bytes.as_slice()),
            (DeltaAction::SetBytes, b"xy".as_slice())
        );
        let u = &gd[b"u".as_slice()];
        assert_eq!((u.action, u.uint), (DeltaAction::SetUint, 7));
        assert_eq!(gd[b"d".as_slice()].action, DeltaAction::Delete);
    }

    /// The encoded `dt` must carry go's numbers on the wire.
    #[test]
    fn encode_eval_delta_emits_go_action_numbers() {
        let mut result = algo_avm::eval::AvmResult::empty();
        result
            .global_delta
            .insert(b"b".to_vec(), Some(TealValue::Bytes(b"xy".to_vec())));
        result
            .global_delta
            .insert(b"u".to_vec(), Some(TealValue::Uint(7)));
        result.global_delta.insert(b"d".to_vec(), None);
        let dt = encode_eval_delta(&result, &Transaction::default(), true).unwrap();
        let Value::Map(top) = dt else { panic!("map") };
        let Value::Map(gd) = &top
            .iter()
            .find(|(k, _)| k.as_str() == Some("gd"))
            .unwrap()
            .1
        else {
            panic!("gd map")
        };
        let at_of = |key: &[u8]| -> u64 {
            let (_, v) = gd
                .iter()
                .find(|(k, _)| matches!(k, Value::String(s) if s.as_bytes() == key))
                .unwrap();
            let Value::Map(m) = v else { panic!("vd map") };
            m.iter()
                .find(|(k, _)| k.as_str() == Some("at"))
                .unwrap()
                .1
                .as_u64()
                .unwrap()
        };
        assert_eq!(at_of(b"b"), 1, "bytes => SetBytesAction = 1");
        assert_eq!(at_of(b"u"), 2, "uint => SetUintAction = 2");
        assert_eq!(at_of(b"d"), 3, "delete => DeleteAction = 3");
    }

    /// Real mainnet evidence (issue #1698); every value below is real.
    ///
    /// Source: mainnet round 65703970, txn index 12 (txid
    /// `PIKRXQRYL7D7APUYCEZ2DOUXLREDUJBSYKCXOGEI72FRJ6DUPC4A`, an app call to
    /// app 1284326447), fetched with
    /// `curl https://mainnet-api.4160.nodely.dev/v2/blocks/65703970?format=msgpack`.
    /// Verbatim: the `at`/`ui`/`bs` of three global-delta keys, `block`
    /// (`at=2`), `last_miner_effort` (`at=2`) and `current_miner` (`at=1`,
    /// 32-byte `bs`). Trimmed (by hand, then checked by decoding): the other
    /// global-delta keys and the rest of the txn were dropped, and the result
    /// was re-packed as `{"gd": {...}}` with str keys. Method (python
    /// `msgpack`): `unpackb(body, raw=True, strict_map_key=False)`, take
    /// `[b"block"][b"txns"][12][b"dt"][b"gd"]`, keep the three keys, pack, hex.
    ///
    /// Cross-checks of the `at` values: the indexer's JSON for the same txn
    /// (`https://mainnet-idx.4160.nodely.dev/v2/blocks/65703970`) reports
    /// `block` action 2, `current_miner` action 1 (with bytes) and
    /// `last_miner_effort` action 2; and the go-generated fixture
    /// `crates/node/algo-rest-api/tests/fixtures/block_json/synthetic_appl.json`
    /// (built by `gen_synthetic.go` with `basics.SetBytesAction` /
    /// `SetUintAction`) uses `at=1` for bytes (`gkey`) and `at=2` for uints
    /// (`cnt`).
    #[test]
    fn parse_real_mainnet_eval_delta_round_65703970() {
        let hex = "81a2676483c405626c6f636b82a2617402a27569ce03ea9022c40d63757272656e745f6d696e657282a2617401a26273c4208802144c5021e7246b08068ada102b27c26f0142e5417830210e024c259aca62c4116c6173745f6d696e65725f6566666f727482a2617402a27569cda028";
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let val = rmpv::decode::read_value(&mut &bytes[..]).unwrap();
        let gd = parse_eval_delta(&val).unwrap().global_delta.unwrap();
        assert_eq!(gd.len(), 3);
        let blk = &gd[b"block".as_slice()];
        assert_eq!((blk.action, blk.uint), (DeltaAction::SetUint, 65703970));
        let eff = &gd[b"last_miner_effort".as_slice()];
        assert_eq!((eff.action, eff.uint), (DeltaAction::SetUint, 41000));
        let miner = &gd[b"current_miner".as_slice()];
        assert_eq!(miner.action, DeltaAction::SetBytes);
        assert_eq!(miner.bytes.len(), 32);
        assert_eq!(miner.uint, 0);
    }

    #[test]
    fn test_parse_empty_eval_delta() {
        let val = Value::Map(vec![]);
        let ed = parse_eval_delta(&val).unwrap();
        assert!(ed.global_delta.is_none());
        assert!(ed.local_deltas.is_none());
        assert!(ed.inner_txns.is_none());
        assert!(ed.logs.is_none());
    }

    #[test]
    fn test_parse_global_delta_set_uint() {
        let val = Value::Map(vec![(
            Value::String("gd".into()),
            Value::Map(vec![(
                Value::String("counter".into()),
                Value::Map(vec![
                    (Value::String("at".into()), Value::Integer(2.into())),
                    (Value::String("ui".into()), Value::Integer(42.into())),
                ]),
            )]),
        )]);

        let ed = parse_eval_delta(&val).unwrap();
        let gd = ed.global_delta.unwrap();
        assert_eq!(gd.len(), 1);
        let vd = gd.get(b"counter".as_slice()).unwrap();
        assert_eq!(vd.action, DeltaAction::SetUint);
        assert_eq!(vd.uint, 42);
        assert!(vd.bytes.is_empty());
    }

    #[test]
    fn test_parse_global_delta_set_bytes() {
        let val = Value::Map(vec![(
            Value::String("gd".into()),
            Value::Map(vec![(
                Value::String("name".into()),
                Value::Map(vec![
                    (Value::String("at".into()), Value::Integer(1.into())),
                    (Value::String("bs".into()), Value::Binary(b"hello".to_vec())),
                ]),
            )]),
        )]);

        let ed = parse_eval_delta(&val).unwrap();
        let gd = ed.global_delta.unwrap();
        let vd = gd.get(b"name".as_slice()).unwrap();
        assert_eq!(vd.action, DeltaAction::SetBytes);
        assert_eq!(vd.bytes, b"hello");
    }

    #[test]
    fn test_parse_global_delta_delete() {
        let val = Value::Map(vec![(
            Value::String("gd".into()),
            Value::Map(vec![(
                Value::String("old_key".into()),
                Value::Map(vec![(Value::String("at".into()), Value::Integer(3.into()))]),
            )]),
        )]);

        let ed = parse_eval_delta(&val).unwrap();
        let gd = ed.global_delta.unwrap();
        let vd = gd.get(b"old_key".as_slice()).unwrap();
        assert_eq!(vd.action, DeltaAction::Delete);
    }

    #[test]
    fn test_parse_local_deltas() {
        let val = Value::Map(vec![(
            Value::String("ld".into()),
            Value::Map(vec![(
                Value::Integer(0.into()),
                Value::Map(vec![(
                    Value::String("opted_in".into()),
                    Value::Map(vec![
                        (Value::String("at".into()), Value::Integer(2.into())),
                        (Value::String("ui".into()), Value::Integer(1.into())),
                    ]),
                )]),
            )]),
        )]);

        let ed = parse_eval_delta(&val).unwrap();
        let ld = ed.local_deltas.unwrap();
        assert_eq!(ld.len(), 1);
        let delta_0 = ld.get(&0).unwrap();
        assert_eq!(delta_0.len(), 1);
        let vd = delta_0.get(b"opted_in".as_slice()).unwrap();
        assert_eq!(vd.action, DeltaAction::SetUint);
        assert_eq!(vd.uint, 1);
    }

    #[test]
    fn test_parse_logs() {
        let val = Value::Map(vec![(
            Value::String("lg".into()),
            Value::Array(vec![
                Value::Binary(b"log line 1".to_vec()),
                Value::Binary(b"log line 2".to_vec()),
            ]),
        )]);

        let ed = parse_eval_delta(&val).unwrap();
        let logs = ed.logs.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0], b"log line 1");
        assert_eq!(logs[1], b"log line 2");
    }

    #[test]
    fn test_parse_nil_fields_ignored() {
        let val = Value::Map(vec![
            (Value::String("gd".into()), Value::Nil),
            (Value::String("ld".into()), Value::Nil),
            (Value::String("itx".into()), Value::Nil),
            (Value::String("lg".into()), Value::Nil),
        ]);

        let ed = parse_eval_delta(&val).unwrap();
        assert!(ed.global_delta.is_none());
        assert!(ed.local_deltas.is_none());
        assert!(ed.inner_txns.is_none());
        assert!(ed.logs.is_none());
    }

    #[test]
    fn test_parse_empty_collections_ignored() {
        let val = Value::Map(vec![
            (Value::String("gd".into()), Value::Map(vec![])),
            (Value::String("ld".into()), Value::Map(vec![])),
            (Value::String("itx".into()), Value::Array(vec![])),
            (Value::String("lg".into()), Value::Array(vec![])),
        ]);

        let ed = parse_eval_delta(&val).unwrap();
        assert!(ed.global_delta.is_none());
        assert!(ed.local_deltas.is_none());
        assert!(ed.inner_txns.is_none());
        assert!(ed.logs.is_none());
    }

    #[test]
    fn test_invalid_action_fails() {
        let val = Value::Map(vec![(
            Value::String("gd".into()),
            Value::Map(vec![(
                Value::String("key".into()),
                Value::Map(vec![(
                    Value::String("at".into()),
                    Value::Integer(99.into()),
                )]),
            )]),
        )]);

        let result = parse_eval_delta(&val);
        assert!(result.is_err());
    }

    #[test]
    fn test_delta_action_try_from() {
        assert_eq!(DeltaAction::try_from(1).unwrap(), DeltaAction::SetBytes);
        assert_eq!(DeltaAction::try_from(2).unwrap(), DeltaAction::SetUint);
        assert_eq!(DeltaAction::try_from(3).unwrap(), DeltaAction::Delete);
        assert!(DeltaAction::try_from(0).is_err());
        assert!(DeltaAction::try_from(4).is_err());
    }

    #[test]
    fn test_unknown_fields_ignored() {
        let val = Value::Map(vec![
            (
                Value::String("gd".into()),
                Value::Map(vec![(
                    Value::String("k".into()),
                    Value::Map(vec![
                        (Value::String("at".into()), Value::Integer(2.into())),
                        (Value::String("ui".into()), Value::Integer(5.into())),
                        // Unknown field in ValueDelta
                        (Value::String("zz".into()), Value::String("ignored".into())),
                    ]),
                )]),
            ),
            // Unknown top-level field
            (Value::String("xx".into()), Value::Integer(999.into())),
        ]);

        let ed = parse_eval_delta(&val).unwrap();
        let gd = ed.global_delta.unwrap();
        let vd = gd.get(b"k".as_slice()).unwrap();
        assert_eq!(vd.action, DeltaAction::SetUint);
        assert_eq!(vd.uint, 5);
    }

    fn avm_result(
        global_delta: HashMap<Vec<u8>, Option<TealValue>>,
        local_deltas: HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>>,
        inner: Vec<SignedTransaction>,
        logs: Vec<Vec<u8>>,
    ) -> algo_avm::eval::AvmResult {
        algo_avm::eval::AvmResult {
            global_delta,
            local_deltas,
            local_delta_order: Vec::new(),
            inner_transactions: inner,
            logs,
            approved: true,
            error: None,
            error_detail: None,
            coverage: algo_avm::machine::OpcodeCoverage::default(),
            scratch: crate::avm_context::default_scratch_row(),
        }
    }

    #[test]
    fn encode_eval_delta_round_trips_through_parse() {
        let sender = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let txn = Transaction {
            sender,
            accounts: Some(vec![other]), // index 1 (sender is index 0)
            ..Default::default()
        };

        let mut global_delta = HashMap::new();
        global_delta.insert(b"gk".to_vec(), Some(TealValue::Uint(42)));
        global_delta.insert(b"gdel".to_vec(), None);
        let mut local = HashMap::new();
        local.insert(b"lk".to_vec(), Some(TealValue::Bytes(b"v".to_vec())));
        let mut local_deltas = HashMap::new();
        local_deltas.insert(other, local);

        let result = avm_result(
            global_delta,
            local_deltas,
            vec![SignedTransaction::default()],
            vec![b"log1".to_vec()],
        );

        let encoded = encode_eval_delta(&result, &txn, false).expect("non-empty delta");
        let parsed = parse_eval_delta(&encoded).expect("encoded delta round-trips through parse");

        let gd = parsed.global_delta.expect("global delta");
        assert_eq!(
            gd.get(b"gk".as_slice()).unwrap().action,
            DeltaAction::SetUint
        );
        assert_eq!(gd.get(b"gk".as_slice()).unwrap().uint, 42);
        assert_eq!(
            gd.get(b"gdel".as_slice()).unwrap().action,
            DeltaAction::Delete
        );

        let ld = parsed.local_deltas.expect("local deltas");
        let l = ld.get(&1).expect("account index 1 (accounts[0])");
        assert_eq!(
            l.get(b"lk".as_slice()).unwrap().action,
            DeltaAction::SetBytes
        );
        assert_eq!(l.get(b"lk".as_slice()).unwrap().bytes, b"v");

        assert_eq!(parsed.logs.expect("logs"), vec![b"log1".to_vec()]);
        assert_eq!(parsed.inner_txns.expect("inner txns").len(), 1);
    }

    /// Matches go's `TestRandomizedEncodingEvalDelta`
    /// (`data/transactions/msgp_gen_test.go`): a fuzz/randomized-instance
    /// variant of [`encode_eval_delta_round_trips_through_parse`] above,
    /// covering many random combinations of global-delta keys/values,
    /// multi-account local deltas, inner-transaction counts, and logs
    /// through the same real `encode_eval_delta` -> `parse_eval_delta`
    /// pair, rather than a single hand-picked scenario.
    #[test]
    fn encode_eval_delta_randomized_roundtrip() {
        use rand::{Rng, RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        fn gen_bytes(rng: &mut ChaCha20Rng, min_len: usize, max_len: usize) -> Vec<u8> {
            let len = rng.gen_range(min_len.max(1)..=max_len.max(min_len.max(1)));
            let mut v = vec![0u8; len];
            rng.fill_bytes(&mut v);
            v
        }

        fn gen_teal_value(rng: &mut ChaCha20Rng) -> Option<TealValue> {
            match rng.gen_range(0..3) {
                0 => None,
                1 => Some(TealValue::Uint(rng.gen())),
                _ => Some(TealValue::Bytes(gen_bytes(rng, 1, 24))),
            }
        }

        fn gen_address(rng: &mut ChaCha20Rng) -> Address {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            Address(bytes)
        }

        const ITERATIONS: usize = 200;
        let mut rng = ChaCha20Rng::seed_from_u64(0x1740_0004);

        for i in 0..ITERATIONS {
            // Build a random set of `accounts[]` addresses on the txn so
            // local-delta account indices resolve deterministically.
            let n_accounts = rng.gen_range(0..=3);
            let accounts: Vec<Address> = (0..n_accounts).map(|_| gen_address(&mut rng)).collect();
            let sender = gen_address(&mut rng);
            let txn = Transaction {
                sender,
                accounts: if accounts.is_empty() {
                    None
                } else {
                    Some(accounts.clone())
                },
                ..Default::default()
            };

            let n_global = rng.gen_range(0..=4);
            let mut global_delta = HashMap::new();
            for _ in 0..n_global {
                global_delta.insert(gen_bytes(&mut rng, 1, 8), gen_teal_value(&mut rng));
            }

            let n_local_accts = rng.gen_range(0..=(1 + accounts.len()));
            let mut local_deltas = HashMap::new();
            let mut candidates = accounts.clone();
            candidates.push(sender);
            for _ in 0..n_local_accts {
                let addr = candidates[rng.gen_range(0..candidates.len())];
                let n_keys = rng.gen_range(0..=3);
                let mut per_key = HashMap::new();
                for _ in 0..n_keys {
                    per_key.insert(gen_bytes(&mut rng, 1, 8), gen_teal_value(&mut rng));
                }
                local_deltas.insert(addr, per_key);
            }

            let n_logs = rng.gen_range(0..=3);
            let logs: Vec<Vec<u8>> = (0..n_logs).map(|_| gen_bytes(&mut rng, 1, 16)).collect();

            let n_inner = rng.gen_range(0..=2);
            let inner: Vec<SignedTransaction> =
                (0..n_inner).map(|_| SignedTransaction::default()).collect();

            let result = avm_result(
                global_delta.clone(),
                local_deltas.clone(),
                inner.clone(),
                logs.clone(),
            );

            let encoded = encode_eval_delta(&result, &txn, false);
            let expect_empty = global_delta.is_empty()
                && local_deltas.is_empty()
                && logs.is_empty()
                && inner.is_empty();
            if expect_empty {
                assert!(
                    encoded.is_none(),
                    "iteration {i}: expected no delta for an all-empty result"
                );
                continue;
            }
            let encoded =
                encoded.unwrap_or_else(|| panic!("iteration {i}: expected non-empty delta"));
            let parsed = parse_eval_delta(&encoded)
                .unwrap_or_else(|e| panic!("iteration {i}: failed to parse: {e}"));

            // Global delta: every original key must decode to the same
            // action/value (a `None` value maps to a Delete action).
            for (k, v) in &global_delta {
                let vd = parsed
                    .global_delta
                    .as_ref()
                    .and_then(|gd| gd.get(k.as_slice()))
                    .unwrap_or_else(|| panic!("iteration {i}: missing global delta key {k:?}"));
                match v {
                    None => assert_eq!(vd.action, DeltaAction::Delete, "iteration {i}"),
                    Some(TealValue::Uint(u)) => {
                        assert_eq!(vd.action, DeltaAction::SetUint, "iteration {i}");
                        assert_eq!(vd.uint, *u, "iteration {i}");
                    }
                    Some(TealValue::Bytes(b)) => {
                        assert_eq!(vd.action, DeltaAction::SetBytes, "iteration {i}");
                        assert_eq!(&vd.bytes, b, "iteration {i}");
                    }
                }
            }

            // Local deltas: every original address's per-key map must
            // appear at its resolved wire index (sender = 0, accounts[j] =
            // j+1), with the same action/value per key.
            for (addr, per_key) in &local_deltas {
                let idx = if *addr == sender {
                    0u64
                } else {
                    accounts
                        .iter()
                        .position(|a| a == addr)
                        .unwrap_or_else(|| panic!("iteration {i}: address not in accounts"))
                        as u64
                        + 1
                };
                let entry = parsed
                    .local_deltas
                    .as_ref()
                    .and_then(|ld| ld.get(&idx))
                    .unwrap_or_else(|| panic!("iteration {i}: missing local delta index {idx}"));
                for (k, v) in per_key {
                    let vd = entry
                        .get(k.as_slice())
                        .unwrap_or_else(|| panic!("iteration {i}: missing local key {k:?}"));
                    match v {
                        None => assert_eq!(vd.action, DeltaAction::Delete, "iteration {i}"),
                        Some(TealValue::Uint(u)) => {
                            assert_eq!(vd.action, DeltaAction::SetUint, "iteration {i}");
                            assert_eq!(vd.uint, *u, "iteration {i}");
                        }
                        Some(TealValue::Bytes(b)) => {
                            assert_eq!(vd.action, DeltaAction::SetBytes, "iteration {i}");
                            assert_eq!(&vd.bytes, b, "iteration {i}");
                        }
                    }
                }
            }

            assert_eq!(
                parsed.inner_txns.as_ref().map(|v| v.len()).unwrap_or(0),
                inner.len(),
                "iteration {i}: inner txn count"
            );
            assert_eq!(
                parsed.logs.clone().unwrap_or_default(),
                logs,
                "iteration {i}: logs"
            );
        }
    }

    #[test]
    fn encode_eval_delta_empty_is_none() {
        let result = avm_result(HashMap::new(), HashMap::new(), vec![], vec![]);
        assert!(encode_eval_delta(&result, &Transaction::default(), false).is_none());
    }

    /// Issue #1280: an opt-in-only touch (address present in `local_deltas`
    /// with an empty per-key map, matching how `LedgerAvmContext::
    /// take_local_deltas` now records `ApplicationOptIn`) must encode as a
    /// real empty `"ld"` entry when `no_empty_local_deltas` is false
    /// (pre-v27), and must be omitted from `"ld"` entirely — and the whole
    /// `"ld"`/`"dt"` map must vanish along with it, since nothing else is
    /// present — when `no_empty_local_deltas` is true (v27+, go's
    /// `ConsensusParams.NoEmptyLocalDeltas`).
    #[test]
    fn encode_eval_delta_opt_in_only_touch_no_empty_local_deltas_gate() {
        let sender = Address([1u8; 32]);
        let txn = Transaction {
            sender,
            ..Default::default()
        };
        let mut local_deltas = HashMap::new();
        local_deltas.insert(sender, HashMap::new()); // opt-in touch, no kv writes
        let result = avm_result(HashMap::new(), local_deltas, vec![], vec![]);

        // Pre-v27: the empty local delta is a real "ld" entry.
        let encoded_pre_v27 =
            encode_eval_delta(&result, &txn, false).expect("pre-v27 must keep the empty ld entry");
        let parsed_pre_v27 = parse_eval_delta(&encoded_pre_v27).unwrap();
        let ld_pre_v27 = parsed_pre_v27
            .local_deltas
            .expect("pre-v27 local_deltas must be Some");
        let sender_delta = ld_pre_v27.get(&0).expect("sender (index 0) entry");
        assert!(
            sender_delta.is_empty(),
            "opt-in-only touch must be an empty per-key map"
        );

        // v27+: NoEmptyLocalDeltas suppresses the entry -- with nothing else
        // in the delta, the whole encoding is None.
        assert!(
            encode_eval_delta(&result, &txn, true).is_none(),
            "v27+ must omit an opt-in-only touch's empty ld entry entirely"
        );
    }

    /// Extract the `sa` (shared accounts) entries from an encoded eval delta.
    fn shared_accts(encoded: &rmpv::Value) -> Vec<Vec<u8>> {
        let rmpv::Value::Map(m) = encoded else {
            return vec![];
        };
        for (k, v) in m {
            if matches!(k, rmpv::Value::String(s) if s.as_str() == Some("sa")) {
                if let rmpv::Value::Array(a) = v {
                    return a
                        .iter()
                        .filter_map(|x| match x {
                            rmpv::Value::Binary(b) => Some(b.clone()),
                            _ => None,
                        })
                        .collect();
                }
            }
        }
        vec![]
    }

    #[test]
    fn encode_eval_delta_routes_raw_account_to_shared_accts() {
        // A local delta for an account that's neither the sender nor in the
        // Accounts array must be recorded under `sa` and indexed after accounts
        // (sender=0, accounts[0]=1, shared[0]=2), not silently dropped.
        let sender = Address([1u8; 32]);
        let acct = Address([2u8; 32]); // in accounts → index 1
        let raw = Address([9u8; 32]); // not in accounts → shared → index 2
        let txn = Transaction {
            sender,
            accounts: Some(vec![acct]),
            ..Default::default()
        };
        let mut local_deltas = HashMap::new();
        for a in [sender, acct, raw] {
            let mut kv = HashMap::new();
            kv.insert(b"k".to_vec(), Some(TealValue::Uint(1)));
            local_deltas.insert(a, kv);
        }

        let encoded = encode_eval_delta(
            &avm_result(HashMap::new(), local_deltas, vec![], vec![]),
            &txn,
            false,
        )
        .expect("delta");

        let parsed = parse_eval_delta(&encoded).unwrap();
        let ld = parsed.local_deltas.unwrap();
        assert!(
            ld.contains_key(&0) && ld.contains_key(&1) && ld.contains_key(&2),
            "expected indices 0/1/2 (sender/accounts[0]/shared[0]), got {:?}",
            ld.keys().collect::<Vec<_>>(),
        );
        assert_eq!(
            shared_accts(&encoded),
            vec![raw.0.to_vec()],
            "raw-address account must appear in the shared-accounts list",
        );
        // parse_eval_delta must now surface `sa` as typed addresses.
        assert_eq!(
            parsed.shared_accts,
            Some(vec![raw]),
            "parse_eval_delta should decode the `sa` shared-accounts list",
        );
    }

    #[test]
    fn parse_eval_delta_decodes_shared_accts() {
        let raw = Address([7u8; 32]);
        let val = Value::Map(vec![(
            Value::String("sa".into()),
            Value::Array(vec![Value::Binary(raw.0.to_vec())]),
        )]);
        let ed = parse_eval_delta(&val).unwrap();
        assert_eq!(ed.shared_accts, Some(vec![raw]));
    }

    #[test]
    fn parse_eval_delta_rejects_malformed_shared_acct() {
        // A non-32-byte entry in `sa` is a hard error, not silently dropped.
        let val = Value::Map(vec![(
            Value::String("sa".into()),
            Value::Array(vec![Value::Binary(vec![1, 2, 3])]),
        )]);
        assert!(parse_eval_delta(&val).is_err());
    }

    #[test]
    fn apply_eval_delta_resolves_shared_account_local_delta() {
        // A local delta indexed past the Accounts array must resolve to the
        // matching `sa` shared account and write that account's local state —
        // not error with "out of bounds" (the pre-TASK-281 behavior).
        use crate::apply::ApplyContext;
        use crate::state::LedgerState;
        use crate::store_trait::LedgerStore;

        let sender = Address([1u8; 32]);
        let in_accounts = Address([2u8; 32]); // index 1
        let shared = Address([9u8; 32]); // index 2 (shared[0])
        let app_id = 555u64;

        let mut store = LedgerState::new();
        store.set_app_params(
            app_id,
            AppParams {
                creator: sender,
                approval_program: Vec::new(),
                clear_state_program: Vec::new(),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
                ..Default::default()
            },
        );

        // Local delta for index 2 → shared[0] → `shared`, setting key "k" = 3.
        let mut kv = HashMap::new();
        kv.insert(
            b"k".to_vec(),
            ValueDelta {
                action: DeltaAction::SetUint,
                uint: 3,
                bytes: Vec::new(),
            },
        );
        let mut local_deltas = HashMap::new();
        local_deltas.insert(2u64, kv);

        let delta = EvalDelta {
            local_deltas: Some(local_deltas),
            shared_accts: Some(vec![shared]),
            ..Default::default()
        };

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: algo_types::TxnType::Appl,
                sender,
                application_id: app_id,
                accounts: Some(vec![in_accounts]),
                ..Default::default()
            },
            ..Default::default()
        };

        let ctx = ApplyContext::new_replay(0, Address::ZERO, 1);
        apply_eval_delta(&stx, &delta, &mut store, &ctx, 0)
            .expect("shared-account local delta should apply cleanly");

        let ls = store
            .get_app_local_state(&shared, app_id)
            .expect("shared account should have local state written");
        assert_eq!(ls.key_value.get(b"k".as_slice()), Some(&TealValue::Uint(3)));
    }

    // ---- Issue #1705: go's canonical EvalDelta/ValueDelta bytes ----------
    //
    // go `basics.ValueDelta` (`data/basics/teal.go`) is `codec:",omitempty"`
    // with `at`/`bs`/`ui`; generated `MarshalMsg` (`data/basics/msgp_gen.go`)
    // drops `at==0`, `bs==""` and `ui==0`, and writes `bs` with
    // `AppendString` (msgpack str, not bin). `StateDelta` sorts its string
    // keys and writes them as str. `transactions.EvalDelta`
    // (`data/transactions/teal.go`) fields are emitted sorted by codec name:
    // gd, itx, ld, lg, sa; `lg` entries are `[]string` (str), `sa` is
    // `[]Address` (bin32), `ld` keys are sorted uint64.

    /// The `dt` bytes exactly as the block encoder writes them: place the
    /// value in a `SignedTransaction`, run the canonical STIB encoder
    /// (`add_option_rmpv("dt")`), decode that map structurally with rmpv and
    /// re-encode only its `dt` value through the str-preserving writer (no
    /// byte-pattern scanning, so key/log bytes cannot mis-slice).
    fn wire(v: &Value) -> Vec<u8> {
        let stx = SignedTransaction {
            eval_delta: Some(v.clone()),
            ..SignedTransaction::default()
        };
        let bytes = algo_codec::canonical_encode_signed_txn_in_block(&stx);
        let Value::Map(top) = rmpv::decode::read_value(&mut &bytes[..]).unwrap() else {
            panic!("stib map")
        };
        let dt = top
            .iter()
            .find(|(k, _)| k.as_str() == Some("dt"))
            .expect("dt present")
            .1
            .clone();
        let mut out = Vec::new();
        algo_codec::write_value_str_preserving(&mut out, &dt).unwrap();
        out
    }

    fn gd_only(entries: Vec<(&[u8], Option<TealValue>)>) -> Vec<u8> {
        let mut result = algo_avm::eval::AvmResult::empty();
        for (k, v) in entries {
            result.global_delta.insert(k.to_vec(), v);
        }
        wire(&encode_eval_delta(&result, &Transaction::default(), true).unwrap())
    }

    /// `{"gd": {"k": <vd>}}` prefix: map1, str2 "gd", map1, str1 "k".
    const GD_K: [u8; 7] = [0x81, 0xa2, b'g', b'd', 0x81, 0xa1, b'k'];

    fn with_gd_k(vd: &[u8]) -> Vec<u8> {
        let mut e = GD_K.to_vec();
        e.extend_from_slice(vd);
        e
    }

    #[test]
    fn value_delta_uint_zero_omits_ui() {
        // {at:2}
        assert_eq!(
            gd_only(vec![(b"k", Some(TealValue::Uint(0)))]),
            with_gd_k(&[0x81, 0xa2, b'a', b't', 0x02])
        );
    }

    #[test]
    fn value_delta_empty_bytes_omits_bs() {
        // {at:1}
        assert_eq!(
            gd_only(vec![(b"k", Some(TealValue::Bytes(vec![])))]),
            with_gd_k(&[0x81, 0xa2, b'a', b't', 0x01])
        );
    }

    #[test]
    fn value_delta_delete_is_only_at() {
        assert_eq!(
            gd_only(vec![(b"k", None)]),
            with_gd_k(&[0x81, 0xa2, b'a', b't', 0x03])
        );
    }

    #[test]
    fn value_delta_nonzero_uint_and_nonempty_bytes_keep_fields() {
        assert_eq!(
            gd_only(vec![(b"k", Some(TealValue::Uint(7)))]),
            with_gd_k(&[0x82, 0xa2, b'a', b't', 0x02, 0xa2, b'u', b'i', 0x07])
        );
        // `bs` is a msgpack str (go AppendString), not bin.
        assert_eq!(
            gd_only(vec![(b"k", Some(TealValue::Bytes(b"xy".to_vec())))]),
            with_gd_k(&[0x82, 0xa2, b'a', b't', 0x01, 0xa2, b'b', b's', 0xa2, b'x', b'y'])
        );
        // Non-UTF-8 bytes are still written as str (raw bytes).
        assert_eq!(
            gd_only(vec![(b"k", Some(TealValue::Bytes(vec![0xff])))]),
            with_gd_k(&[0x82, 0xa2, b'a', b't', 0x01, 0xa2, b'b', b's', 0xa1, 0xff])
        );
    }

    /// A mix in one `gd`: keys sorted bytewise and written as str, each value
    /// delta omitting its zero fields.
    #[test]
    fn state_delta_mix_sorted_str_keys() {
        let got = gd_only(vec![
            (b"zz", Some(TealValue::Uint(0))),
            (b"a", Some(TealValue::Bytes(b"q".to_vec()))),
            (b"m", None),
            (&[0xff], Some(TealValue::Uint(1))),
            (b"b", Some(TealValue::Bytes(vec![]))),
        ]);
        let want: Vec<u8> = vec![
            0x81, 0xa2, b'g', b'd', 0x85, // gd: 5 entries
            0xa1, b'a', 0x82, 0xa2, b'a', b't', 0x01, 0xa2, b'b', b's', 0xa1, b'q', //
            0xa1, b'b', 0x81, 0xa2, b'a', b't', 0x01, //
            0xa1, b'm', 0x81, 0xa2, b'a', b't', 0x03, //
            0xa2, b'z', b'z', 0x81, 0xa2, b'a', b't', 0x02, //
            0xa1, 0xff, 0x82, 0xa2, b'a', b't', 0x02, 0xa2, b'u', b'i', 0x01,
        ];
        // 0xff sorts after every ASCII key (go `SortString` is bytewise).
        assert_eq!(got, want);
    }

    /// Whole EvalDelta: field order gd, ld, lg, sa (itx absent), `ld` keys
    /// ascending, `lg` entries str, `sa` entries bin32.
    #[test]
    fn eval_delta_field_order_and_typing() {
        let sender = Address([1u8; 32]);
        let acct = Address([2u8; 32]);
        let raw = Address([3u8; 32]);
        let txn = Transaction {
            sender,
            accounts: Some(vec![acct]),
            ..Transaction::default()
        };
        let mut result = algo_avm::eval::AvmResult::empty();
        result
            .global_delta
            .insert(b"g".to_vec(), Some(TealValue::Uint(0)));
        for a in [raw, acct, sender] {
            result
                .local_deltas
                .entry(a)
                .or_default()
                .insert(b"l".to_vec(), Some(TealValue::Bytes(vec![])));
        }
        result.logs = vec![b"hi".to_vec(), vec![0xfe]];
        let got = wire(&encode_eval_delta(&result, &txn, true).unwrap());

        let ld_entry = |idx: u8| -> Vec<u8> {
            vec![
                idx, 0x81, 0xa1, b'l', 0x81, 0xa2, b'a', b't', 0x01, // idx: {l: {at:1}}
            ]
        };
        let mut want: Vec<u8> = vec![0x84];
        want.extend([
            0xa2, b'g', b'd', 0x81, 0xa1, b'g', 0x81, 0xa2, b'a', b't', 0x02,
        ]);
        want.extend([0xa2, b'l', b'd', 0x83]);
        want.extend(ld_entry(0)); // sender
        want.extend(ld_entry(1)); // accounts[0]
        want.extend(ld_entry(2)); // sa[0]
        want.extend([0xa2, b'l', b'g', 0x92, 0xa2, b'h', b'i', 0xa1, 0xfe]);
        want.extend([0xa2, b's', b'a', 0x91, 0xc4, 0x20]);
        want.extend([3u8; 32]);
        assert_eq!(got, want);
    }

    /// Decode accepts both the omitted and the explicit zero forms (and the
    /// legacy bin/str spellings) and yields the same `ValueDelta`.
    #[test]
    fn parse_value_delta_omitted_and_explicit_zero_agree() {
        let omitted = Value::Map(vec![(Value::from("at"), Value::from(2u64))]);
        let explicit = Value::Map(vec![
            (Value::from("at"), Value::from(2u64)),
            (Value::from("ui"), Value::from(0u64)),
            (Value::from("bs"), Value::Binary(vec![])),
        ]);
        assert_eq!(
            parse_value_delta(&omitted).unwrap(),
            parse_value_delta(&explicit).unwrap()
        );
        let b_omitted = Value::Map(vec![(Value::from("at"), Value::from(1u64))]);
        let b_explicit = Value::Map(vec![
            (Value::from("at"), Value::from(1u64)),
            (Value::from("bs"), Value::from("")),
            (Value::from("ui"), Value::from(0u64)),
        ]);
        let d = parse_value_delta(&b_omitted).unwrap();
        assert_eq!(d, parse_value_delta(&b_explicit).unwrap());
        assert_eq!(
            (d.action, d.uint, d.bytes.len()),
            (DeltaAction::SetBytes, 0, 0)
        );
    }

    /// Encode -> wire -> decode of a str-typed non-UTF-8 key/value survives.
    #[test]
    fn non_utf8_str_keys_and_bs_roundtrip_through_wire() {
        let bytes = gd_only(vec![(
            &[0xff, 0x00],
            Some(TealValue::Bytes(vec![0xfe, 0x80])),
        )]);
        let v = rmpv::decode::read_value(&mut &bytes[..]).unwrap();
        let ed = parse_eval_delta(&v).unwrap();
        let gd = ed.global_delta.unwrap();
        let vd = &gd[&vec![0xffu8, 0x00]];
        assert_eq!(vd.bytes, vec![0xfe, 0x80]);
        assert_eq!(wire(&v), bytes, "re-encoding the decoded value is stable");
    }

    /// Issue #1705 review: a nested `itx` entry's own `dt` must keep str
    /// typing for non-UTF-8 keys/logs at every depth (rmp_serde + read_value
    /// of the inner stx turned them into bin).
    #[test]
    fn inner_txn_dt_keeps_str_for_non_utf8_at_depth() {
        let mut child = algo_avm::eval::AvmResult::empty();
        child
            .global_delta
            .insert(vec![0xff], Some(TealValue::Bytes(vec![0x80])));
        child.logs = vec![vec![0xfe]];
        let child_dt = encode_eval_delta(&child, &Transaction::default(), true);
        let inner = SignedTransaction {
            eval_delta: child_dt,
            ..SignedTransaction::default()
        };
        let mut parent = algo_avm::eval::AvmResult::empty();
        parent.inner_transactions = vec![inner];
        let dt = encode_eval_delta(&parent, &Transaction::default(), true).unwrap();
        let bytes = wire(&dt);
        let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(has(&[0xa1, 0xff]), "inner gd key must be str");
        assert!(has(&[0xa2, b'b', b's', 0xa1, 0x80]), "inner bs must be str");
        assert!(
            has(&[0xa2, b'l', b'g', 0x91, 0xa1, 0xfe]),
            "inner lg must be str"
        );
        assert!(
            !has(&[0xc4, 0x01, 0xff]) && !has(&[0xc4, 0x01, 0xfe]) && !has(&[0xc4, 0x01, 0x80])
        );
    }

    // ---- Issue #1739: canonical `itx` (go `SignedTxnWithAD`) --------------
    //
    // go `EvalDelta.InnerTxns` is `[]SignedTxnWithAD`
    // (`data/transactions/teal.go`); `SignedTxnWithAD` embeds `SignedTxn` +
    // `ApplyData` with `codec:",omitempty,omitemptyarray"`
    // (`data/transactions/signedtxn.go`), so each entry is a map of the
    // non-zero fields sorted by codec name (aca, apid, ca, caid, dt, lsig,
    // msig, pqsig, rc, rr, rs, sgnr, sig, txn) with NO `hgi`/`hgh`
    // (those belong to `SignedTxnInBlock` only), zero fields omitted and
    // an all-zero struct as the one-byte empty map.

    fn fixstr(b: &[u8]) -> Vec<u8> {
        let mut v = vec![0xa0 | b.len() as u8];
        v.extend_from_slice(b);
        v
    }

    fn bin32(b: u8) -> Vec<u8> {
        let mut v = vec![0xc4, 0x20];
        v.extend_from_slice(&[b; 32]);
        v
    }

    fn appl_child_with_non_utf8_dt() -> SignedTransaction {
        let mut child = algo_avm::eval::AvmResult::empty();
        child
            .global_delta
            .insert(vec![0xff], Some(TealValue::Bytes(vec![0x80])));
        child.logs = vec![vec![0xfe]];
        SignedTransaction {
            txn: Transaction {
                txn_type: algo_types::TxnType::Appl,
                sender: Address([7u8; 32]),
                application_id: 5,
                ..Default::default()
            },
            apply_data_application_id: 9,
            eval_delta: encode_eval_delta(&child, &Transaction::default(), true),
            ..Default::default()
        }
    }

    fn pay_child_zero_fields() -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: algo_types::TxnType::Pay,
                sender: Address([1u8; 32]),
                receiver: Address([2u8; 32]),
                amount: 0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn three_children() -> Vec<SignedTransaction> {
        vec![
            appl_child_with_non_utf8_dt(),
            pay_child_zero_fields(),
            SignedTransaction::default(),
        ]
    }

    #[test]
    fn itx_entries_are_canonical_signed_txn_with_ad_bytes() {
        let mut parent = algo_avm::eval::AvmResult::empty();
        parent.inner_transactions = three_children();
        let dt = encode_eval_delta(&parent, &Transaction::default(), true).unwrap();

        let child_dt = [
            vec![0x82],
            fixstr(b"gd"),
            vec![0x81, 0xa1, 0xff, 0x82],
            fixstr(b"at"),
            vec![0x01],
            fixstr(b"bs"),
            vec![0xa1, 0x80],
            fixstr(b"lg"),
            vec![0x91, 0xa1, 0xfe],
        ]
        .concat();
        let appl = [
            vec![0x83],
            fixstr(b"apid"),
            vec![0x09],
            fixstr(b"dt"),
            child_dt,
            fixstr(b"txn"),
            vec![0x83],
            fixstr(b"apid"),
            vec![0x05],
            fixstr(b"snd"),
            bin32(7),
            fixstr(b"type"),
            fixstr(b"appl"),
        ]
        .concat();
        let pay = [
            vec![0x81],
            fixstr(b"txn"),
            vec![0x83],
            fixstr(b"rcv"),
            bin32(2),
            fixstr(b"snd"),
            bin32(1),
            fixstr(b"type"),
            fixstr(b"pay"),
        ]
        .concat();
        let expected = [
            vec![0x81],
            fixstr(b"itx"),
            vec![0x93],
            appl,
            pay,
            vec![0x80],
        ]
        .concat();
        assert_eq!(wire(&dt), expected);
    }

    #[test]
    fn parse_inner_txns_reads_canonical_itx_and_keeps_non_utf8_str() {
        let mut parent = algo_avm::eval::AvmResult::empty();
        parent.inner_transactions = three_children();
        let dt = encode_eval_delta(&parent, &Transaction::default(), true).unwrap();
        let before = wire(&dt);
        // Wire round trip, as a block decode would hand it to the parser.
        let parsed_val = rmpv::decode::read_value(&mut &before[..]).unwrap();
        let parsed = parse_eval_delta(&parsed_val).unwrap();
        let inner = parsed.inner_txns.unwrap();
        assert_eq!(inner.len(), 3);
        assert_eq!(inner[0].txn.application_id, 5);
        assert_eq!(inner[0].apply_data_application_id, 9);
        assert_eq!(inner[1].txn.receiver, Address([2u8; 32]));
        assert_eq!(inner[2], SignedTransaction::default());
        // Re-encoding the parsed children must reproduce the same bytes
        // (non-UTF-8 str typing in the nested dt survives the parse).
        let mut again = algo_avm::eval::AvmResult::empty();
        again.inner_transactions = inner;
        let dt2 = encode_eval_delta(&again, &Transaction::default(), true).unwrap();
        assert_eq!(wire(&dt2), before);
    }

    #[test]
    fn parse_inner_txns_still_reads_legacy_named_serde_form() {
        // Blocks stored by earlier builds carry rmp_serde named-struct
        // entries (all fields incl. empty `txn`); they must still parse.
        let legacy = rmp_serde::to_vec_named(&pay_child_zero_fields()).unwrap();
        let v = rmpv::decode::read_value(&mut &legacy[..]).unwrap();
        let list = parse_inner_txns(&Value::Array(vec![v])).unwrap();
        assert_eq!(list[0].txn.receiver, Address([2u8; 32]));
    }

    /// Issue #1740: local deltas are keyed by a function of the address, so
    /// two distinct addresses can never share an `ld` key; the sender that is
    /// also in `accounts` is index 0, and an account listed twice resolves to
    /// its first slot.
    #[test]
    fn ld_keys_are_unique_when_sender_and_accounts_overlap() {
        let sender = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let txn = Transaction {
            sender,
            accounts: Some(vec![sender, other, other]),
            ..Default::default()
        };
        let mut r = algo_avm::eval::AvmResult::empty();
        for a in [sender, other] {
            r.local_deltas.insert(
                a,
                HashMap::from([(b"k".to_vec(), Some(TealValue::Uint(1)))]),
            );
        }
        let dt = encode_eval_delta(&r, &txn, true).unwrap();
        let Value::Map(top) = dt else { panic!() };
        let ld = top.iter().find(|(k, _)| k.as_str() == Some("ld")).unwrap();
        let Value::Map(ld) = &ld.1 else { panic!() };
        let keys: Vec<u64> = ld.iter().map(|(k, _)| k.as_u64().unwrap()).collect();
        assert_eq!(keys, vec![0, 2]);
    }

    /// Issue #1740: `sa` is appended in the order the local deltas were first
    /// created (go `ensureLocalDelta`), not in address order; indices follow
    /// (`1 + len(accounts) + position`), and an account already in `accounts`
    /// never enters `sa`.
    #[test]
    fn sa_follows_first_creation_order_not_address_order() {
        let sender = Address([1u8; 32]);
        let listed = Address([5u8; 32]);
        let first = Address([9u8; 32]);
        let second = Address([3u8; 32]);
        let txn = Transaction {
            sender,
            accounts: Some(vec![listed]),
            ..Default::default()
        };
        let mut r = algo_avm::eval::AvmResult::empty();
        for a in [sender, listed, first, second] {
            r.local_deltas.insert(
                a,
                HashMap::from([(b"k".to_vec(), Some(TealValue::Uint(1)))]),
            );
        }
        r.local_delta_order = vec![first, listed, second, sender];
        let dt = encode_eval_delta(&r, &txn, true).unwrap();
        assert_eq!(shared_accts(&dt), vec![first.0.to_vec(), second.0.to_vec()]);
        let Value::Map(top) = &dt else { panic!() };
        let ld = top.iter().find(|(k, _)| k.as_str() == Some("ld")).unwrap();
        let Value::Map(ld) = &ld.1 else { panic!() };
        let keys: Vec<u64> = ld.iter().map(|(k, _)| k.as_u64().unwrap()).collect();
        assert_eq!(keys, vec![0, 1, 2, 3]);
        // `first` (idx 2) precedes `second` (idx 3) although its address is larger.
        let parsed = parse_eval_delta(&dt).unwrap();
        assert_eq!(parsed.shared_accts.unwrap(), vec![first, second]);
    }

    /// Byte-exact oracle from go-algorand output (issue #1739). Real mainnet
    /// round 53000003, txn index 3 (an app call that issued four inner
    /// transactions, one of which is itself an app call with its own `dt`
    /// carrying `itx` and `lg`): the `itx` value of that txn's `dt`, 987 bytes,
    /// sliced verbatim from
    /// `https://mainnet-api.algonode.cloud/v2/blocks/53000003?format=msgpack`
    /// (public chain data, no trimming or re-encoding). Every inner txn must
    /// decode and re-encode through the canonical `SignedTxnWithAD` encoder to
    /// the identical bytes.
    const MAINNET_53000003_TXN3_ITX_HEX: &str = concat!(
        "9282a2647482a36974789482a3616361ce026487cfa374786e87a661636c6f7365c420d41b66fe68886dea8a7a710342",
        "3d1ca26d59cc5a31c507283b3743e194cc21d6a461726376c420d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c5",
        "07283b3743e194cc21d6a26676ce0328b741a26c76ce0328b74ba3736e64c42040582705e7d416b9d6adfefd04766748",
        "bfbf8c7f08f311f6710e4d113431ba89a474797065a56178666572a478616964ce01e1ab7081a374786e87a661636c6f",
        "7365c420d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a461726376c420d41b66fe68",
        "886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a26676ce0328b741a26c76ce0328b74ba3736e64c4",
        "2040582705e7d416b9d6adfefd04766748bfbf8c7f08f311f6710e4d113431ba89a474797065a56178666572a4786169",
        "64cebbcb467881a374786e87a661636c6f7365c420d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743",
        "e194cc21d6a461726376c420d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a26676ce",
        "0328b741a26c76ce0328b74ba3736e64c42040582705e7d416b9d6adfefd04766748bfbf8c7f08f311f6710e4d113431",
        "ba89a474797065a56178666572a478616964cebbcb467982a26361ce00061a80a374786e86a5636c6f7365c420d41b66",
        "fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a26676ce0328b741a26c76ce0328b74ba37263",
        "76c420d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a3736e64c42040582705e7d416",
        "b9d6adfefd04766748bfbf8c7f08f311f6710e4d113431ba89a474797065a3706179a26c6791a5151f7c7501a374786e",
        "8aa46170616191c404119e3c4ba46170616e05a46170617393ce01e1ab70cebbcb4678cebbcb4679a46170617492c420",
        "d41b66fe68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6c420d41b66fe68886dea8a7a7103423d",
        "1ca26d59cc5a31c507283b3743e194cc21d6a46170666191cebbcb4370a461706964cebd9c7172a26676ce0328b741a2",
        "6c76ce0328b74ba3736e64c420a0dfb3d0fb23f8456469ea6688fa89b770291f0fb069f35e3abc1b82b4183ff3a47479",
        "7065a46170706c81a374786e86a3616d74ce00087dd4a26676ce0328b741a26c76ce0328b74ba3726376c420d41b66fe",
        "68886dea8a7a7103423d1ca26d59cc5a31c507283b3743e194cc21d6a3736e64c420a0dfb3d0fb23f8456469ea6688fa",
        "89b770291f0fb069f35e3abc1b82b4183ff3a474797065a3706179"
    );

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mainnet_itx_round_trips_byte_exact_through_canonical_encoder() {
        let go_bytes = unhex(MAINNET_53000003_TXN3_ITX_HEX);
        assert_eq!(go_bytes.len(), 987);
        let go_val = rmpv::decode::read_value(&mut &go_bytes[..]).unwrap();
        let inner = parse_inner_txns(&go_val).unwrap();
        assert_eq!(inner.len(), 2);

        // Per-entry and whole-array byte equality with go's output.
        let mut rebuilt = vec![0x92];
        for stx in &inner {
            rebuilt.extend_from_slice(&algo_codec::canonical_encode_signed_txn_with_ad(stx));
        }
        assert_eq!(rebuilt, go_bytes);

        // And through the full producer path: the parent's `dt` is `{itx: ..}`.
        let mut parent = algo_avm::eval::AvmResult::empty();
        parent.inner_transactions = inner;
        let dt = encode_eval_delta(&parent, &Transaction::default(), true).unwrap();
        let mut expected = vec![0x81];
        expected.extend_from_slice(&fixstr(b"itx"));
        expected.extend_from_slice(&go_bytes);
        assert_eq!(wire(&dt), expected);
    }
}
