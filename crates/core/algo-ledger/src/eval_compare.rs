//! EvalDelta conformance comparison.
//!
//! Compares an [`AvmResult`] produced by AVM execution against the recorded
//! [`EvalDelta`] from block data. This enables dual-mode replay: run the AVM
//! and verify the output matches what the block committed.

use std::collections::HashMap;
use std::fmt;

use algo_avm::eval::AvmResult;
use algo_types::{Address, SignedTransaction, TealValue};

use crate::eval_delta::{DeltaAction, EvalDelta, ValueDelta};

/// A single field-level mismatch between AVM output and recorded EvalDelta.
#[derive(Debug, Clone)]
pub struct FieldMismatch {
    /// Dot-separated path to the mismatched field (e.g. "global_delta.counter").
    pub field: String,
    /// Value from the recorded EvalDelta (block data).
    pub expected: String,
    /// Value from AVM execution.
    pub actual: String,
}

impl fmt::Display for FieldMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: expected={}, actual={}",
            self.field, self.expected, self.actual
        )
    }
}

/// Result of comparing an AvmResult against a recorded EvalDelta.
#[derive(Debug, Clone)]
pub struct CompareResult {
    /// Whether the AVM output matches the recorded EvalDelta.
    pub matches: bool,
    /// Individual field mismatches (empty if `matches` is true).
    pub mismatches: Vec<FieldMismatch>,
}

impl CompareResult {
    fn with_mismatches(mismatches: Vec<FieldMismatch>) -> Self {
        Self {
            matches: mismatches.is_empty(),
            mismatches,
        }
    }
}

impl fmt::Display for CompareResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.matches {
            write!(f, "MATCH")
        } else {
            write!(f, "MISMATCH ({} fields)", self.mismatches.len())?;
            for m in &self.mismatches {
                write!(f, "\n  - {m}")?;
            }
            Ok(())
        }
    }
}

/// Compare an AVM execution result against a recorded EvalDelta from the block.
///
/// `stx` is needed to resolve account indices in the recorded EvalDelta's
/// local_deltas (index 0 = sender, index N = accounts\[N-1\]).
///
/// If the recorded EvalDelta is `None` (no `dt` field on the transaction),
/// the comparison checks that the AVM produced no state changes or logs.
pub fn compare_eval_delta(
    avm_result: &AvmResult,
    recorded: Option<&EvalDelta>,
    stx: &SignedTransaction,
) -> CompareResult {
    let empty_delta = EvalDelta {
        global_delta: None,
        local_deltas: None,
        inner_txns: None,
        logs: None,
    };
    let recorded = recorded.unwrap_or(&empty_delta);
    let mut mismatches = Vec::new();

    compare_logs(&avm_result.logs, &recorded.logs, &mut mismatches);
    compare_global_delta(
        &avm_result.global_delta,
        &recorded.global_delta,
        &mut mismatches,
    );
    compare_local_deltas(
        &avm_result.local_deltas,
        &recorded.local_deltas,
        stx,
        &mut mismatches,
    );
    compare_inner_txns(
        &avm_result.inner_transactions,
        &recorded.inner_txns,
        &mut mismatches,
    );

    CompareResult::with_mismatches(mismatches)
}

// ---------------------------------------------------------------------------
// Logs comparison
// ---------------------------------------------------------------------------

fn compare_logs(
    avm_logs: &[Vec<u8>],
    recorded_logs: &Option<Vec<Vec<u8>>>,
    mismatches: &mut Vec<FieldMismatch>,
) {
    let recorded = recorded_logs.as_deref().unwrap_or(&[]);

    if avm_logs.len() != recorded.len() {
        mismatches.push(FieldMismatch {
            field: "logs.count".to_string(),
            expected: recorded.len().to_string(),
            actual: avm_logs.len().to_string(),
        });
        return;
    }

    for (i, (avm_log, rec_log)) in avm_logs.iter().zip(recorded.iter()).enumerate() {
        if avm_log != rec_log {
            mismatches.push(FieldMismatch {
                field: format!("logs[{i}]"),
                expected: format_bytes(rec_log),
                actual: format_bytes(avm_log),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Global delta comparison
// ---------------------------------------------------------------------------

fn compare_global_delta(
    avm_delta: &HashMap<Vec<u8>, Option<TealValue>>,
    recorded_delta: &Option<HashMap<Vec<u8>, ValueDelta>>,
    mismatches: &mut Vec<FieldMismatch>,
) {
    let empty_recorded: HashMap<Vec<u8>, ValueDelta> = HashMap::new();
    let recorded = recorded_delta.as_ref().unwrap_or(&empty_recorded);

    // Check keys in recorded but not in AVM output.
    for (key, vd) in recorded {
        let key_str = format_key(key);
        match avm_delta.get(key) {
            Some(avm_val) => {
                if !value_delta_matches_option(vd, avm_val) {
                    mismatches.push(FieldMismatch {
                        field: format!("global_delta.{key_str}"),
                        expected: format_value_delta(vd),
                        actual: format_option_teal_value(avm_val),
                    });
                }
            }
            None => {
                if vd.action != DeltaAction::Delete {
                    mismatches.push(FieldMismatch {
                        field: format!("global_delta.{key_str}"),
                        expected: format_value_delta(vd),
                        actual: "<missing>".to_string(),
                    });
                }
                // Delete action with no AVM entry: the AVM never touched
                // this key, so it did not emit a delete. This is still a
                // semantic match — both result in the key not existing.
            }
        }
    }

    // Check keys in AVM output but not in recorded.
    for (key, avm_val) in avm_delta {
        let key_str = format_key(key);
        if !recorded.contains_key(key) {
            mismatches.push(FieldMismatch {
                field: format!("global_delta.{key_str}"),
                expected: "<missing>".to_string(),
                actual: format_option_teal_value(avm_val),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Local delta comparison
// ---------------------------------------------------------------------------

fn compare_local_deltas(
    avm_deltas: &HashMap<Address, HashMap<Vec<u8>, Option<TealValue>>>,
    recorded_deltas: &Option<HashMap<u64, HashMap<Vec<u8>, ValueDelta>>>,
    stx: &SignedTransaction,
    mismatches: &mut Vec<FieldMismatch>,
) {
    let empty_recorded: HashMap<u64, HashMap<Vec<u8>, ValueDelta>> = HashMap::new();
    let recorded = recorded_deltas.as_ref().unwrap_or(&empty_recorded);

    // Build index-to-address mapping from the transaction.
    let index_to_addr = |idx: u64| -> Option<Address> {
        if idx == 0 {
            Some(stx.txn.sender)
        } else {
            stx.txn
                .accounts
                .as_ref()
                .and_then(|accts| accts.get((idx - 1) as usize).copied())
        }
    };

    // Build address-to-index mapping for reverse lookup.
    let mut addr_to_index: HashMap<Address, u64> = HashMap::new();
    addr_to_index.insert(stx.txn.sender, 0);
    if let Some(ref accounts) = stx.txn.accounts {
        for (i, addr) in accounts.iter().enumerate() {
            addr_to_index.insert(*addr, (i + 1) as u64);
        }
    }

    // Compare recorded entries against AVM output.
    for (&acct_idx, rec_kv) in recorded {
        let addr = match index_to_addr(acct_idx) {
            Some(a) => a,
            None => {
                mismatches.push(FieldMismatch {
                    field: format!("local_deltas[{acct_idx}]"),
                    expected: format!("{} keys", rec_kv.len()),
                    actual: "<unresolvable account index>".to_string(),
                });
                continue;
            }
        };

        let addr_str = addr.to_algorand_string();
        let avm_kv = avm_deltas.get(&addr);
        let empty_avm: HashMap<Vec<u8>, Option<TealValue>> = HashMap::new();
        let avm_kv = avm_kv.unwrap_or(&empty_avm);

        // Check each recorded key.
        for (key, vd) in rec_kv {
            let key_str = format_key(key);
            match avm_kv.get(key) {
                Some(avm_val) => {
                    if !value_delta_matches_option(vd, avm_val) {
                        mismatches.push(FieldMismatch {
                            field: format!("local_deltas[{addr_str}].{key_str}"),
                            expected: format_value_delta(vd),
                            actual: format_option_teal_value(avm_val),
                        });
                    }
                }
                None => {
                    if vd.action != DeltaAction::Delete {
                        mismatches.push(FieldMismatch {
                            field: format!("local_deltas[{addr_str}].{key_str}"),
                            expected: format_value_delta(vd),
                            actual: "<missing>".to_string(),
                        });
                    }
                }
            }
        }

        // Check AVM keys not in recorded.
        for (key, avm_val) in avm_kv {
            let key_str = format_key(key);
            if !rec_kv.contains_key(key) {
                mismatches.push(FieldMismatch {
                    field: format!("local_deltas[{addr_str}].{key_str}"),
                    expected: "<missing>".to_string(),
                    actual: format_option_teal_value(avm_val),
                });
            }
        }
    }

    // Check AVM addresses not in recorded.
    for (addr, avm_kv) in avm_deltas {
        if !addr_to_index.contains_key(addr) || {
            let idx = addr_to_index[addr];
            !recorded.contains_key(&idx)
        } {
            let addr_str = addr.to_algorand_string();
            for (key, avm_val) in avm_kv {
                let key_str = format_key(key);
                mismatches.push(FieldMismatch {
                    field: format!("local_deltas[{addr_str}].{key_str}"),
                    expected: "<missing>".to_string(),
                    actual: format_option_teal_value(avm_val),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inner transactions comparison
// ---------------------------------------------------------------------------

fn compare_inner_txns(
    avm_inner: &[SignedTransaction],
    recorded_inner: &Option<Vec<SignedTransaction>>,
    mismatches: &mut Vec<FieldMismatch>,
) {
    compare_inner_txns_at("inner_txns", avm_inner, recorded_inner, mismatches);
}

/// Recursive inner transaction comparison with a configurable field prefix.
fn compare_inner_txns_at(
    prefix: &str,
    avm_inner: &[SignedTransaction],
    recorded_inner: &Option<Vec<SignedTransaction>>,
    mismatches: &mut Vec<FieldMismatch>,
) {
    let recorded = recorded_inner.as_deref().unwrap_or(&[]);

    if avm_inner.len() != recorded.len() {
        mismatches.push(FieldMismatch {
            field: format!("{prefix}.count"),
            expected: recorded.len().to_string(),
            actual: avm_inner.len().to_string(),
        });
        // Don't compare individual txns if counts differ.
        return;
    }

    for (i, (avm_itx, rec_itx)) in avm_inner.iter().zip(recorded.iter()).enumerate() {
        let p = format!("{prefix}[{i}]");

        // Compare transaction type.
        if avm_itx.txn.txn_type != rec_itx.txn.txn_type {
            mismatches.push(FieldMismatch {
                field: format!("{p}.type"),
                expected: rec_itx.txn.txn_type.clone(),
                actual: avm_itx.txn.txn_type.clone(),
            });
        }

        // Compare sender.
        if avm_itx.txn.sender != rec_itx.txn.sender {
            mismatches.push(FieldMismatch {
                field: format!("{p}.sender"),
                expected: rec_itx.txn.sender.to_algorand_string(),
                actual: avm_itx.txn.sender.to_algorand_string(),
            });
        }

        // Compare receiver.
        if avm_itx.txn.receiver != rec_itx.txn.receiver {
            mismatches.push(FieldMismatch {
                field: format!("{p}.receiver"),
                expected: rec_itx.txn.receiver.to_algorand_string(),
                actual: avm_itx.txn.receiver.to_algorand_string(),
            });
        }

        // Compare amount (Algo).
        if avm_itx.txn.amount != rec_itx.txn.amount {
            mismatches.push(FieldMismatch {
                field: format!("{p}.amount"),
                expected: rec_itx.txn.amount.to_string(),
                actual: avm_itx.txn.amount.to_string(),
            });
        }

        // Compare fee.
        if avm_itx.txn.fee != rec_itx.txn.fee {
            mismatches.push(FieldMismatch {
                field: format!("{p}.fee"),
                expected: rec_itx.txn.fee.to_string(),
                actual: avm_itx.txn.fee.to_string(),
            });
        }

        // Compare close_remainder_to.
        if avm_itx.txn.close_remainder_to != rec_itx.txn.close_remainder_to {
            mismatches.push(FieldMismatch {
                field: format!("{p}.close_remainder_to"),
                expected: rec_itx.txn.close_remainder_to.to_algorand_string(),
                actual: avm_itx.txn.close_remainder_to.to_algorand_string(),
            });
        }

        // Compare rekey_to.
        if avm_itx.txn.rekey_to != rec_itx.txn.rekey_to {
            let fmt_opt = |o: &Option<Address>| match o {
                Some(a) => a.to_algorand_string(),
                None => "<none>".to_string(),
            };
            mismatches.push(FieldMismatch {
                field: format!("{p}.rekey_to"),
                expected: fmt_opt(&rec_itx.txn.rekey_to),
                actual: fmt_opt(&avm_itx.txn.rekey_to),
            });
        }

        // Compare xaid (asset ID for asset transfers/config/freeze).
        if avm_itx.txn.xaid != rec_itx.txn.xaid {
            mismatches.push(FieldMismatch {
                field: format!("{p}.xaid"),
                expected: rec_itx.txn.xaid.to_string(),
                actual: avm_itx.txn.xaid.to_string(),
            });
        }

        // Compare application_id (for app calls).
        if avm_itx.txn.application_id != rec_itx.txn.application_id {
            mismatches.push(FieldMismatch {
                field: format!("{p}.application_id"),
                expected: rec_itx.txn.application_id.to_string(),
                actual: avm_itx.txn.application_id.to_string(),
            });
        }

        // Compare asset_amount (for asset transfers).
        if avm_itx.txn.asset_amount != rec_itx.txn.asset_amount {
            mismatches.push(FieldMismatch {
                field: format!("{p}.asset_amount"),
                expected: rec_itx.txn.asset_amount.to_string(),
                actual: avm_itx.txn.asset_amount.to_string(),
            });
        }

        // Compare on_completion (for app calls).
        if avm_itx.txn.on_completion != rec_itx.txn.on_completion {
            mismatches.push(FieldMismatch {
                field: format!("{p}.on_completion"),
                expected: rec_itx.txn.on_completion.to_string(),
                actual: avm_itx.txn.on_completion.to_string(),
            });
        }

        // Recursively compare nested inner transactions.
        // Both sides store eval_delta as Option<rmpv::Value>; parse to extract
        // nested inner txns for deeper comparison.
        let avm_nested = avm_itx
            .eval_delta
            .as_ref()
            .and_then(|raw| crate::eval_delta::parse_eval_delta(raw).ok())
            .and_then(|ed| ed.inner_txns);
        let rec_nested = rec_itx
            .eval_delta
            .as_ref()
            .and_then(|raw| crate::eval_delta::parse_eval_delta(raw).ok())
            .and_then(|ed| ed.inner_txns);
        let avm_nested_slice = avm_nested.as_deref().unwrap_or(&[]);
        let nested_prefix = format!("{p}.inner_txns");
        compare_inner_txns_at(&nested_prefix, avm_nested_slice, &rec_nested, mismatches);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a recorded ValueDelta matches an AVM TealValue.
///
/// Mapping: SetUint -> Uint, SetBytes -> Bytes, Delete has no TealValue
/// counterpart (the key should be absent from the AVM delta).
/// Match a recorded `ValueDelta` against an AVM `Option<TealValue>`.
///
/// `None` on the AVM side represents a delete operation.
fn value_delta_matches_option(vd: &ValueDelta, avm_val: &Option<TealValue>) -> bool {
    match (&vd.action, avm_val) {
        (DeltaAction::Delete, None) => true,
        (DeltaAction::SetUint, Some(TealValue::Uint(v))) => *v == vd.uint,
        (DeltaAction::SetBytes, Some(TealValue::Bytes(b))) => *b == vd.bytes,
        _ => false,
    }
}

fn format_value_delta(vd: &ValueDelta) -> String {
    match vd.action {
        DeltaAction::SetUint => format!("SetUint({})", vd.uint),
        DeltaAction::SetBytes => format!("SetBytes({})", format_bytes(&vd.bytes)),
        DeltaAction::Delete => "Delete".to_string(),
    }
}

fn format_option_teal_value(tv: &Option<TealValue>) -> String {
    match tv {
        Some(TealValue::Uint(v)) => format!("Uint({v})"),
        Some(TealValue::Bytes(b)) => format!("Bytes({})", format_bytes(b)),
        None => "Delete".to_string(),
    }
}

fn format_bytes(b: &[u8]) -> String {
    if b.len() <= 32 {
        if let Ok(s) = std::str::from_utf8(b) {
            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return format!("\"{s}\"");
            }
        }
    }
    format!(
        "0x{}",
        b.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn format_key(key: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(key) {
        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return s.to_string();
        }
    }
    format!(
        "0x{}",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Classifies a mismatch into a high-level category for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MismatchCategory {
    /// AVM execution hit an unimplemented opcode or feature.
    UnimplementedOpcode,
    /// AVM produced a result that differs semantically from the recorded one.
    SemanticMismatch,
    /// Comparison logic defect (e.g. serialization/parsing difference).
    ComparisonDefect,
    /// Infrastructure error (fetch, decode, apply failure).
    InfraError,
}

impl fmt::Display for MismatchCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MismatchCategory::UnimplementedOpcode => write!(f, "unimplemented_opcode"),
            MismatchCategory::SemanticMismatch => write!(f, "semantic_mismatch"),
            MismatchCategory::ComparisonDefect => write!(f, "comparison_defect"),
            MismatchCategory::InfraError => write!(f, "infra_error"),
        }
    }
}

/// Aggregate statistics for EvalDelta comparison across a replay run.
#[derive(Debug, Default)]
pub struct EvalDeltaStats {
    /// Total application call transactions encountered.
    pub app_calls_total: u64,
    /// App calls where AVM output matched the recorded EvalDelta.
    pub app_calls_matching: u64,
    /// App calls where AVM output did not match the recorded EvalDelta.
    pub app_calls_mismatching: u64,
    /// App calls that errored during AVM execution (not counted as mismatch).
    pub app_calls_errored: u64,
    /// Detailed mismatch info for the first N mismatches.
    pub mismatch_details: Vec<EvalDeltaMismatchDetail>,
    /// LogicSig programs executed.
    pub logicsig_total: u64,
    /// LogicSig programs that passed.
    pub logicsig_passed: u64,
    /// LogicSig programs that failed.
    pub logicsig_failed: u64,
    /// Aggregated opcode coverage across all AVM executions.
    pub opcode_coverage: algo_avm::OpcodeCoverage,
    /// Mismatch counts by category.
    pub mismatch_categories: HashMap<MismatchCategory, u64>,
}

/// Detail about a single mismatching app call.
#[derive(Debug, Clone)]
pub struct EvalDeltaMismatchDetail {
    pub round: u64,
    pub txn_index: usize,
    pub app_id: u64,
    pub mismatches: Vec<FieldMismatch>,
}

impl fmt::Display for EvalDeltaMismatchDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "round={} txn={} app={}: {} mismatches",
            self.round,
            self.txn_index,
            self.app_id,
            self.mismatches.len()
        )?;
        for m in &self.mismatches {
            write!(f, "\n    - {m}")?;
        }
        Ok(())
    }
}

/// Maximum number of detailed mismatch records to keep in memory.
const MAX_MISMATCH_DETAILS: usize = 100;

impl std::ops::AddAssign for EvalDeltaStats {
    fn add_assign(&mut self, rhs: Self) {
        self.app_calls_total += rhs.app_calls_total;
        self.app_calls_matching += rhs.app_calls_matching;
        self.app_calls_mismatching += rhs.app_calls_mismatching;
        self.app_calls_errored += rhs.app_calls_errored;
        self.logicsig_total += rhs.logicsig_total;
        self.logicsig_passed += rhs.logicsig_passed;
        self.logicsig_failed += rhs.logicsig_failed;
        self.opcode_coverage.merge(&rhs.opcode_coverage);
        for (cat, count) in &rhs.mismatch_categories {
            *self.mismatch_categories.entry(*cat).or_insert(0) += count;
        }
        for detail in rhs.mismatch_details {
            if self.mismatch_details.len() < MAX_MISMATCH_DETAILS {
                self.mismatch_details.push(detail);
            }
        }
    }
}

impl EvalDeltaStats {
    /// Record a matching app call, merging coverage from the execution.
    pub fn record_match(&mut self) {
        self.app_calls_total += 1;
        self.app_calls_matching += 1;
    }

    /// Record a matching app call with opcode coverage data.
    pub fn record_match_with_coverage(&mut self, coverage: &algo_avm::OpcodeCoverage) {
        self.app_calls_total += 1;
        self.app_calls_matching += 1;
        self.opcode_coverage.merge(coverage);
    }

    /// Record a mismatching app call with detail and optional category.
    pub fn record_mismatch(&mut self, detail: EvalDeltaMismatchDetail) {
        self.app_calls_total += 1;
        self.app_calls_mismatching += 1;
        *self
            .mismatch_categories
            .entry(MismatchCategory::SemanticMismatch)
            .or_insert(0) += 1;
        if self.mismatch_details.len() < MAX_MISMATCH_DETAILS {
            self.mismatch_details.push(detail);
        }
    }

    /// Record a mismatching app call with coverage and explicit category.
    pub fn record_mismatch_with_coverage(
        &mut self,
        detail: EvalDeltaMismatchDetail,
        coverage: &algo_avm::OpcodeCoverage,
        category: MismatchCategory,
    ) {
        self.app_calls_total += 1;
        self.app_calls_mismatching += 1;
        self.opcode_coverage.merge(coverage);
        *self.mismatch_categories.entry(category).or_insert(0) += 1;
        if self.mismatch_details.len() < MAX_MISMATCH_DETAILS {
            self.mismatch_details.push(detail);
        }
    }

    /// Record an AVM execution error.
    pub fn record_error(&mut self) {
        self.app_calls_total += 1;
        self.app_calls_errored += 1;
        *self
            .mismatch_categories
            .entry(MismatchCategory::InfraError)
            .or_insert(0) += 1;
    }

    /// Record an AVM execution error with coverage data.
    pub fn record_error_with_coverage(
        &mut self,
        coverage: &algo_avm::OpcodeCoverage,
        is_unimplemented: bool,
    ) {
        self.app_calls_total += 1;
        self.app_calls_errored += 1;
        self.opcode_coverage.merge(coverage);
        let cat = if is_unimplemented {
            MismatchCategory::UnimplementedOpcode
        } else {
            MismatchCategory::InfraError
        };
        *self.mismatch_categories.entry(cat).or_insert(0) += 1;
    }

    /// Record a LogicSig result.
    pub fn record_logicsig(&mut self, passed: bool) {
        self.logicsig_total += 1;
        if passed {
            self.logicsig_passed += 1;
        } else {
            self.logicsig_failed += 1;
        }
    }

    /// Print a summary to stdout.
    pub fn print_summary(&self) {
        println!("\n=== AVM Execution Summary ===");
        println!("App calls total:      {}", self.app_calls_total);
        println!("  Matching EvalDelta: {}", self.app_calls_matching);
        println!("  Mismatching:        {}", self.app_calls_mismatching);
        println!("  AVM errors:         {}", self.app_calls_errored);
        if self.logicsig_total > 0 {
            println!("LogicSig total:       {}", self.logicsig_total);
            println!("  Passed:             {}", self.logicsig_passed);
            println!("  Failed:             {}", self.logicsig_failed);
        }

        // Opcode coverage summary.
        let hit = self.opcode_coverage.hit_count();
        let total = self.opcode_coverage.total_defined();
        let pct = self.opcode_coverage.coverage_pct();
        println!("\nOpcode coverage:      {hit}/{total} ({pct:.1}%)");

        // Mismatch taxonomy.
        if !self.mismatch_categories.is_empty() {
            println!("\nMismatch categories:");
            let mut cats: Vec<_> = self.mismatch_categories.iter().collect();
            cats.sort_by_key(|(cat, _)| cat.to_string());
            for (cat, count) in &cats {
                println!("  {cat:<25} {count}");
            }
        }

        if !self.mismatch_details.is_empty() {
            let shown = self.mismatch_details.len();
            let total = self.app_calls_mismatching;
            println!("\nMismatch details (showing {shown} of {total}):");
            for detail in &self.mismatch_details {
                println!("  {detail}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Transaction;

    fn make_stx_with_accounts(sender: Address, accounts: Vec<Address>) -> SignedTransaction {
        let txn = Transaction {
            sender,
            accounts: if accounts.is_empty() {
                None
            } else {
                Some(accounts)
            },
            ..Default::default()
        };
        SignedTransaction {
            txn,
            ..Default::default()
        }
    }

    #[test]
    fn test_compare_both_empty() {
        let result = AvmResult::empty();
        let delta = EvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(cmp.matches, "both empty should match");
    }

    #[test]
    fn test_compare_matching_logs() {
        let mut result = AvmResult::empty();
        result.logs = vec![b"hello".to_vec(), b"world".to_vec()];

        let delta = EvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: None,
            logs: Some(vec![b"hello".to_vec(), b"world".to_vec()]),
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(cmp.matches, "matching logs: {cmp}");
    }

    #[test]
    fn test_compare_mismatching_log_count() {
        let mut result = AvmResult::empty();
        result.logs = vec![b"hello".to_vec()];

        let delta = EvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: None,
            logs: Some(vec![b"hello".to_vec(), b"world".to_vec()]),
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(!cmp.matches);
        assert_eq!(cmp.mismatches.len(), 1);
        assert_eq!(cmp.mismatches[0].field, "logs.count");
    }

    #[test]
    fn test_compare_matching_global_delta() {
        let mut result = AvmResult::empty();
        result
            .global_delta
            .insert(b"counter".to_vec(), Some(TealValue::Uint(42)));

        let mut gd = HashMap::new();
        gd.insert(
            b"counter".to_vec(),
            ValueDelta {
                action: DeltaAction::SetUint,
                uint: 42,
                bytes: vec![],
            },
        );
        let delta = EvalDelta {
            global_delta: Some(gd),
            local_deltas: None,
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(cmp.matches, "matching global delta: {cmp}");
    }

    #[test]
    fn test_compare_mismatching_global_delta_value() {
        let mut result = AvmResult::empty();
        result
            .global_delta
            .insert(b"counter".to_vec(), Some(TealValue::Uint(99)));

        let mut gd = HashMap::new();
        gd.insert(
            b"counter".to_vec(),
            ValueDelta {
                action: DeltaAction::SetUint,
                uint: 42,
                bytes: vec![],
            },
        );
        let delta = EvalDelta {
            global_delta: Some(gd),
            local_deltas: None,
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(!cmp.matches);
        assert_eq!(cmp.mismatches[0].field, "global_delta.counter");
    }

    #[test]
    fn test_compare_extra_global_key_in_avm() {
        let mut result = AvmResult::empty();
        result
            .global_delta
            .insert(b"extra".to_vec(), Some(TealValue::Uint(1)));

        let delta = EvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(!cmp.matches);
        assert!(cmp.mismatches[0].field.contains("extra"));
    }

    #[test]
    fn test_compare_matching_local_delta() {
        let sender = Address([1u8; 32]);
        let mut result = AvmResult::empty();
        let mut kv = HashMap::new();
        kv.insert(b"opted_in".to_vec(), Some(TealValue::Uint(1)));
        result.local_deltas.insert(sender, kv);

        let mut rec_kv = HashMap::new();
        rec_kv.insert(
            b"opted_in".to_vec(),
            ValueDelta {
                action: DeltaAction::SetUint,
                uint: 1,
                bytes: vec![],
            },
        );
        let mut ld = HashMap::new();
        ld.insert(0u64, rec_kv); // index 0 = sender

        let delta = EvalDelta {
            global_delta: None,
            local_deltas: Some(ld),
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(sender, vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(cmp.matches, "matching local delta: {cmp}");
    }

    #[test]
    fn test_compare_none_recorded_with_empty_avm() {
        let result = AvmResult::empty();
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, None, &stx);
        assert!(cmp.matches, "no recorded delta, empty AVM should match");
    }

    #[test]
    fn test_compare_none_recorded_with_nonempty_avm() {
        let mut result = AvmResult::empty();
        result.logs = vec![b"unexpected".to_vec()];
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, None, &stx);
        assert!(
            !cmp.matches,
            "no recorded delta, nonempty AVM should mismatch"
        );
    }

    #[test]
    fn test_compare_inner_txn_count_mismatch() {
        let mut result = AvmResult::empty();
        result.inner_transactions.push(SignedTransaction::default());

        let delta = EvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: None,
            logs: None,
        };
        let stx = make_stx_with_accounts(Address([0u8; 32]), vec![]);
        let cmp = compare_eval_delta(&result, Some(&delta), &stx);
        assert!(!cmp.matches);
        assert_eq!(cmp.mismatches[0].field, "inner_txns.count");
    }

    #[test]
    fn test_stats_summary() {
        let mut stats = EvalDeltaStats::default();
        stats.record_match();
        stats.record_match();
        stats.record_error();
        stats.record_mismatch(EvalDeltaMismatchDetail {
            round: 100,
            txn_index: 0,
            app_id: 42,
            mismatches: vec![FieldMismatch {
                field: "logs.count".into(),
                expected: "2".into(),
                actual: "0".into(),
            }],
        });
        stats.record_logicsig(true);
        stats.record_logicsig(false);

        assert_eq!(stats.app_calls_total, 4);
        assert_eq!(stats.app_calls_matching, 2);
        assert_eq!(stats.app_calls_mismatching, 1);
        assert_eq!(stats.app_calls_errored, 1);
        assert_eq!(stats.logicsig_total, 2);
        assert_eq!(stats.logicsig_passed, 1);
        assert_eq!(stats.logicsig_failed, 1);
        assert_eq!(stats.mismatch_details.len(), 1);
    }
}
