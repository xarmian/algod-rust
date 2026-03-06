use std::collections::HashMap;

use algo_error::AlgoError;
use algo_types::{AppLocalState, AppParams, SignedTransaction, StateSchema, TealValue};

use crate::apply::{apply_transaction, ApplyContext};
use crate::state::LedgerState;

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
#[derive(Debug, Clone, PartialEq)]
pub struct EvalDelta {
    /// Global state changes keyed by state key.
    pub global_delta: Option<HashMap<Vec<u8>, ValueDelta>>,
    /// Per-account local state changes. Outer key is the account index
    /// (offset into the transaction's Accounts array), inner key is state key.
    pub local_deltas: Option<HashMap<u64, HashMap<Vec<u8>, ValueDelta>>>,
    /// Inner transactions (each with their own ApplyData/EvalDelta).
    pub inner_txns: Option<Vec<SignedTransaction>>,
    /// Log messages emitted by the application.
    pub logs: Option<Vec<Vec<u8>>>,
}

/// Parse an EvalDelta from an rmpv::Value (the `dt` field on SignedTransaction).
///
/// The rmpv::Value is expected to be a Map with string keys:
/// - "gd": global delta (map of string key -> ValueDelta map)
/// - "ld": local deltas (map of uint index -> map of string key -> ValueDelta map)
/// - "itx": inner transactions (array of msgpack-encoded SignedTransaction)
/// - "lg": logs (array of binary/string values)
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
    })
}

/// Maximum inner transaction recursion depth.
const MAX_INNER_TXN_DEPTH: u32 = 256;

/// Apply a parsed EvalDelta to the ledger state.
///
/// Updates global state, local state, and recursively applies inner transactions.
pub fn apply_eval_delta(
    stx: &SignedTransaction,
    delta: &EvalDelta,
    state: &mut LedgerState,
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
            let app = state.app_params.entry(app_id).or_insert_with(|| AppParams {
                creator: txn.sender,
                approval_program: Vec::new(),
                clear_state_program: Vec::new(),
                global_state: std::collections::BTreeMap::new(),
                local_state_schema: StateSchema::default(),
                global_state_schema: StateSchema::default(),
                extra_program_pages: 0,
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
        }
    }

    // Apply local deltas.
    if let Some(ref ld) = delta.local_deltas {
        if app_id != 0 {
            for (&account_index, kv_deltas) in ld {
                // Resolve account address: index 0 = sender, index N = accounts[N-1].
                let addr = if account_index == 0 {
                    txn.sender
                } else {
                    let accounts = txn.accounts.as_ref().ok_or_else(|| AlgoError::Ledger {
                        message: format!(
                            "eval_delta local: account index {} but no accounts array on txn",
                            account_index
                        ),
                    })?;
                    let idx = (account_index - 1) as usize;
                    *accounts.get(idx).ok_or_else(|| AlgoError::Ledger {
                        message: format!(
                            "eval_delta local: account index {} out of bounds (accounts len {})",
                            account_index,
                            accounts.len()
                        ),
                    })?
                };

                // Get or create local state entry. For recorded block replay,
                // the account should already be opted in. If not (e.g. opt-in
                // happened in an inner txn earlier in this call), create a
                // placeholder — the OptIn branch in apply_appl will fix up
                // the schema and counter afterward.
                let local = state
                    .app_local_states
                    .entry((addr, app_id))
                    .or_insert_with(|| AppLocalState {
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
            }
        }
    }

    // Recursively apply inner transactions.
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
            apply_transaction(state, inner_stx, ctx, depth + 1)?;
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
}
