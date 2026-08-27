use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{
    Address, AppLocalState, AppParams, SignedTransaction, StateSchema, TealValue, Transaction,
};

use crate::apply::{apply_transaction, ApplyContext};

// NOTE: LedgerStore is referenced via full path in function bounds rather
// than imported at module level. See apply.rs for rationale.

/// Action types for state delta changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DeltaAction {
    SetUint = 1,
    SetBytes = 2,
    Delete = 3,
}

impl TryFrom<u64> for DeltaAction {
    type Error = AlgoError;

    fn try_from(v: u64) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(DeltaAction::SetUint),
            2 => Ok(DeltaAction::SetBytes),
            3 => Ok(DeltaAction::Delete),
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
pub fn encode_eval_delta(
    result: &algo_avm::eval::AvmResult,
    txn: &Transaction,
) -> Option<rmpv::Value> {
    use rmpv::Value;

    // A single key→value change: {at: action, ui|bs: value}.
    fn value_delta(v: &Option<TealValue>) -> Value {
        match v {
            Some(TealValue::Uint(u)) => Value::Map(vec![
                (Value::from("at"), Value::from(DeltaAction::SetUint as u64)),
                (Value::from("ui"), Value::from(*u)),
            ]),
            Some(TealValue::Bytes(b)) => Value::Map(vec![
                (Value::from("at"), Value::from(DeltaAction::SetBytes as u64)),
                (Value::from("bs"), Value::Binary(b.clone())),
            ]),
            None => Value::Map(vec![(
                Value::from("at"),
                Value::from(DeltaAction::Delete as u64),
            )]),
        }
    }

    // A state-delta map: state-key (binary) → value delta.
    fn state_delta(m: &HashMap<Vec<u8>, Option<TealValue>>) -> Value {
        Value::Map(
            m.iter()
                .map(|(k, v)| (Value::Binary(k.clone()), value_delta(v)))
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
        let mut items: Vec<_> = result.local_deltas.iter().collect();
        items.sort_by_key(|(addr, _)| addr.0);

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
        entries.push((Value::from("ld"), Value::Map(ld)));
        if !shared.is_empty() {
            // `sa`: addresses for the local deltas that index beyond `accounts`.
            entries.push((
                Value::from("sa"),
                Value::Array(shared.iter().map(|a| Value::Binary(a.0.to_vec())).collect()),
            ));
        }
    }

    if !result.inner_transactions.is_empty() {
        // Each inner transaction is an msgpack-encoded SignedTransaction, the
        // same shape `parse_inner_txns` reads back.
        let itx: Vec<Value> = result
            .inner_transactions
            .iter()
            .filter_map(|stx| {
                let bytes = rmp_serde::to_vec_named(stx).ok()?;
                rmpv::decode::read_value(&mut &bytes[..]).ok()
            })
            .collect();
        if !itx.is_empty() {
            entries.push((Value::from("itx"), Value::Array(itx)));
        }
    }

    if !result.logs.is_empty() {
        let lg: Vec<Value> = result
            .logs
            .iter()
            .map(|l| Value::Binary(l.clone()))
            .collect();
        entries.push((Value::from("lg"), Value::Array(lg)));
    }

    if entries.is_empty() {
        None
    } else {
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
        // Serialize the rmpv::Value to msgpack bytes, then deserialize into SignedTransaction.
        let mut msgpack_bytes = Vec::new();
        rmpv::encode::write_value(&mut msgpack_bytes, item).map_err(|e| AlgoError::Codec {
            source: Box::new(e),
            context: "inner_txn: failed to encode rmpv to msgpack".to_string(),
        })?;
        let stx: SignedTransaction =
            rmp_serde::from_slice(&msgpack_bytes).map_err(|e| AlgoError::Codec {
                source: Box::new(e),
                context: "inner_txn: failed to decode SignedTransaction".to_string(),
            })?;
        txns.push(stx);
    }
    Ok(txns)
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
                    (Value::String("at".into()), Value::Integer(1.into())),
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
                    (Value::String("at".into()), Value::Integer(2.into())),
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
                        (Value::String("at".into()), Value::Integer(1.into())),
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
        assert_eq!(DeltaAction::try_from(1).unwrap(), DeltaAction::SetUint);
        assert_eq!(DeltaAction::try_from(2).unwrap(), DeltaAction::SetBytes);
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
                        (Value::String("at".into()), Value::Integer(1.into())),
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
            inner_transactions: inner,
            logs,
            approved: true,
            error: None,
            coverage: algo_avm::machine::OpcodeCoverage::default(),
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

        let encoded = encode_eval_delta(&result, &txn).expect("non-empty delta");
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

    #[test]
    fn encode_eval_delta_empty_is_none() {
        let result = avm_result(HashMap::new(), HashMap::new(), vec![], vec![]);
        assert!(encode_eval_delta(&result, &Transaction::default()).is_none());
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
}
