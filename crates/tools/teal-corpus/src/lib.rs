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

//! Offline batch driver for the Phase 25 TEAL corpus parity check (#2366,
//! epic #2364).
//!
//! Reads a corpus laid out by `scripts/teal-corpus/extract.py`
//! (`programs/<sha256>.bin`, `sources/<sha256>.teal`) and runs one operation
//! over every input through the same library calls the Rust REST handlers
//! use (`algo_avm::disassembler::disassemble`,
//! `algo_avm::assembler::assemble_string`), writing JSONL rows keyed by the
//! sha256 of the input bytes. `tools/teal-corpus` (Go) emits the identical
//! schema from `logic.Disassemble` / `logic.AssembleString`, and [`diff_files`]
//! compares two such files.
//!
//! Row schema (keys in alphabetical order; absent keys are omitted):
//!
//! * `disassemble`: `{"ok":true,"sha256":..,"text":..}` or
//!   `{"error":..,"ok":false,"sha256":..}`
//! * `assemble`: `{"bytecode_b64":..,"hash":..,"ok":true,"sha256":..,
//!   "sourcemap":{..},"warnings":[{col,line,message}]}` (`warnings` only when
//!   non-empty) or `{"errors":[{col,line,message}],"ok":false,"sha256":..}`
//! * a panic is `{"ok":false,"panic":msg,"sha256":..}`, a per-input time
//!   budget overrun `{"ok":false,"sha256":..,"timeout":true}`.
//!
//! Non-UTF-8 assembler input is rejected identically by both drivers with the
//! single error [`INVALID_UTF8`] at line 0 / column 0 (the Rust assembler takes
//! `&str`; the REST handler layer is covered separately by #2370).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512_256};

/// Output schema version written to the header line.
pub const SCHEMA_VERSION: u32 = 1;

/// Error message used by both drivers for assembler input that is not UTF-8.
pub const INVALID_UTF8: &str = "input is not valid UTF-8";

const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Disassemble,
    Assemble,
}

impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Operation::Disassemble => "disassemble",
            Operation::Assemble => "assemble",
        }
    }

    /// Sub-directory of the corpus holding this operation's inputs.
    pub fn input_subdir(self) -> &'static str {
        match self {
            Operation::Disassemble => "programs",
            Operation::Assemble => "sources",
        }
    }

    /// File extension of this operation's inputs.
    pub fn input_ext(self) -> &'static str {
        match self {
            Operation::Disassemble => "bin",
            Operation::Assemble => "teal",
        }
    }
}

/// One assembler error or warning, exactly as the implementation reports it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Diag {
    pub col: usize,
    pub line: usize,
    pub message: String,
}

/// One output row. Field order is alphabetical to match the Go driver.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Row {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<Diag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panic: Option<String>,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sourcemap: Option<algo_avm::sourcemap::SourceMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<Diag>>,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub sha256: String,
    pub bytes: Arc<Vec<u8>>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Load every `*.<ext>` regular file of `dir`, keyed by the sha256 of its
/// content (never trusting the file name), de-duplicated, sorted by sha256.
pub fn load_inputs(dir: &Path, ext: &str) -> io::Result<Vec<Input>> {
    let mut by_sha: BTreeMap<String, Input> = BTreeMap::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some(ext) {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let sha256 = sha256_hex(&bytes);
        by_sha.entry(sha256.clone()).or_insert(Input {
            sha256,
            bytes: Arc::new(bytes),
        });
    }
    Ok(by_sha.into_values().collect())
}

/// The program hash as `TealCompile` reports it: the SHA512/256 of
/// `"Program" || program` rendered as an Algorand address.
pub fn program_hash(program: &[u8]) -> String {
    let mut h = Sha512_256::new();
    h.update(b"Program");
    h.update(program);
    let digest: [u8; 32] = h.finalize().into();
    algo_types::Address(digest).to_algorand_string()
}

/// Run `op` on one input through the library entry points.
pub fn process(op: Operation, input: &Input) -> Row {
    let mut row = Row {
        sha256: input.sha256.clone(),
        ..Row::default()
    };
    match op {
        Operation::Disassemble => match algo_avm::disassembler::disassemble(&input.bytes) {
            Ok(text) => {
                row.ok = true;
                row.text = Some(text);
            }
            Err(e) => row.error = Some(e),
        },
        Operation::Assemble => {
            let source = match std::str::from_utf8(&input.bytes) {
                Ok(s) => s,
                Err(_) => {
                    row.errors = Some(vec![Diag {
                        col: 0,
                        line: 0,
                        message: INVALID_UTF8.to_string(),
                    }]);
                    return row;
                }
            };
            match algo_avm::assembler::assemble_string(source) {
                Ok(ops) => {
                    row.ok = true;
                    row.bytecode_b64 =
                        Some(base64::engine::general_purpose::STANDARD.encode(&ops.program));
                    row.hash = Some(program_hash(&ops.program));
                    row.sourcemap = Some(algo_avm::sourcemap::get_source_map(
                        vec!["<body>".to_string()],
                        &ops.offset_to_source,
                    ));
                    if !ops.warnings.is_empty() {
                        row.warnings = Some(
                            ops.warnings
                                .iter()
                                .map(|w| Diag {
                                    col: w.col,
                                    line: w.line,
                                    message: w.message.clone(),
                                })
                                .collect(),
                        );
                    }
                }
                Err(errors) => {
                    row.errors = Some(
                        errors
                            .iter()
                            .map(|e| Diag {
                                col: e.col,
                                line: e.line,
                                message: e.message.clone(),
                            })
                            .collect(),
                    );
                }
            }
        }
    }
    row
}

/// Silence the default panic message: panics are recorded in the row instead.
pub fn install_quiet_panic_hook() {
    std::panic::set_hook(Box::new(|_| {}));
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn run_one<F>(f: &Arc<F>, input: &Arc<Input>, timeout: Duration) -> Row
where
    F: Fn(&Input) -> Row + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel();
    let (f2, in2) = (Arc::clone(f), Arc::clone(input));
    let spawned = std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f2(&in2)));
            let _ = tx.send(r.map_err(|p| panic_message(&*p)));
        });
    let failure = |panic: Option<String>, timeout: Option<bool>| Row {
        ok: false,
        panic,
        sha256: input.sha256.clone(),
        timeout,
        ..Row::default()
    };
    if let Err(e) = spawned {
        return failure(Some(format!("failed to spawn worker thread: {e}")), None);
    }
    match rx.recv_timeout(timeout) {
        Ok(Ok(row)) => row,
        Ok(Err(msg)) => failure(Some(msg), None),
        // The overrunning thread cannot be killed; it is abandoned and the
        // process exits once the batch is written.
        Err(mpsc::RecvTimeoutError::Timeout) => failure(None, Some(true)),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            failure(Some("worker thread vanished".to_string()), None)
        }
    }
}

/// Run `f` over every input on `jobs` workers, each input on its own thread
/// under `catch_unwind` with a per-input `timeout`. Rows come back sorted by
/// sha256, independent of scheduling.
pub fn run_batch<F>(inputs: Vec<Input>, jobs: usize, timeout: Duration, f: F) -> Vec<Row>
where
    F: Fn(&Input) -> Row + Send + Sync + 'static,
{
    let f = Arc::new(f);
    let inputs: Vec<Arc<Input>> = inputs.into_iter().map(Arc::new).collect();
    let results: Mutex<Vec<Row>> = Mutex::new(Vec::with_capacity(inputs.len()));
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..jobs.max(1).min(inputs.len().max(1)) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(input) = inputs.get(i) else { break };
                let row = run_one(&f, input, timeout);
                results.lock().unwrap_or_else(|e| e.into_inner()).push(row);
            });
        }
    });
    let mut rows = results.into_inner().unwrap_or_else(|e| e.into_inner());
    rows.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    rows
}

/// True when any row is a recorded panic or timeout.
pub fn has_robustness_failure(rows: &[Row]) -> bool {
    rows.iter()
        .any(|r| r.panic.is_some() || r.timeout == Some(true))
}

/// Header line plus one line per row, newline-terminated.
pub fn render_output(op: Operation, rows: &[Row]) -> String {
    let header = json!({"header": {
        "count": rows.len(),
        "impl": "algod-rust",
        "operation": op.name(),
        "schema": SCHEMA_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
    }});
    let mut out = header.to_string();
    out.push('\n');
    for r in rows {
        out.push_str(&serde_json::to_string(r).expect("row serializes"));
        out.push('\n');
    }
    out
}

/// Result of comparing two driver outputs.
#[derive(Debug)]
pub struct DiffReport {
    pub operation: String,
    pub compared: usize,
    pub left_header: Value,
    pub right_header: Value,
    /// One `{sha256, operation, field, first_diff, left, right}` per differing row.
    pub mismatches: Vec<Value>,
}

type Parsed = (BTreeMap<String, Value>, Value);

fn read_rows(path: &Path) -> Result<Parsed, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut rows = BTreeMap::new();
    let mut header = Value::Null;
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: bad JSON: {e}", path.display(), n + 1))?;
        if let Some(h) = v.get("header") {
            header = h.clone();
            continue;
        }
        let sha = v
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{}:{}: row without sha256", path.display(), n + 1))?
            .to_string();
        if rows.insert(sha.clone(), v).is_some() {
            return Err(format!("{}: duplicate sha256 {sha}", path.display()));
        }
    }
    Ok((rows, header))
}

fn first_diff(field: &str, l: &Value, r: &Value) -> Value {
    match (l, r) {
        (Value::String(a), Value::String(b)) => {
            if field == "bytecode_b64" {
                let eng = base64::engine::general_purpose::STANDARD;
                if let (Ok(x), Ok(y)) = (eng.decode(a), eng.decode(b)) {
                    let at = x.iter().zip(&y).take_while(|(p, q)| p == q).count();
                    return json!({"kind": "offset", "at": at});
                }
            }
            let la: Vec<&str> = a.split('\n').collect();
            let lb: Vec<&str> = b.split('\n').collect();
            let at = la.iter().zip(&lb).take_while(|(p, q)| p == q).count() + 1;
            json!({"kind": "line", "at": at})
        }
        (Value::Array(a), Value::Array(b)) => {
            let at = a.iter().zip(b).take_while(|(p, q)| p == q).count();
            json!({"kind": "index", "at": at})
        }
        _ => json!({"kind": "value", "at": null}),
    }
}

/// Compare two driver outputs row by row (headers are ignored except for the
/// operation, which must agree).
pub fn diff_files(left: &Path, right: &Path) -> Result<DiffReport, String> {
    let (lrows, lh) = read_rows(left)?;
    let (rrows, rh) = read_rows(right)?;
    let op_of = |h: &Value| {
        h.get("operation")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let operation = match (op_of(&lh), op_of(&rh)) {
        (Some(a), Some(b)) if a != b => {
            return Err(format!("operation mismatch: {a} vs {b}"));
        }
        (Some(a), _) | (_, Some(a)) => a,
        (None, None) => "unknown".to_string(),
    };
    let shas: BTreeSet<&String> = lrows.keys().chain(rrows.keys()).collect();
    let mut mismatches = Vec::new();
    for sha in &shas {
        let (l, r) = (lrows.get(*sha), rrows.get(*sha));
        let (field, fd, lv, rv) = match (l, r) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(a), Some(b)) => {
                let keys: BTreeSet<&String> = a
                    .as_object()
                    .into_iter()
                    .chain(b.as_object())
                    .flat_map(|o| o.keys())
                    .collect();
                let key = keys
                    .into_iter()
                    .find(|k| a.get(k.as_str()) != b.get(k.as_str()))
                    .map(String::as_str)
                    .unwrap_or("row");
                let x = a.get(key).cloned().unwrap_or(Value::Null);
                let y = b.get(key).cloned().unwrap_or(Value::Null);
                (key.to_string(), first_diff(key, &x, &y), x, y)
            }
            (a, b) => (
                "row".to_string(),
                json!({"kind": "presence", "at": null}),
                a.cloned().unwrap_or(Value::Null),
                b.cloned().unwrap_or(Value::Null),
            ),
        };
        mismatches.push(json!({
            "field": field,
            "first_diff": fd,
            "left": lv,
            "operation": operation,
            "right": rv,
            "sha256": sha,
        }));
    }
    Ok(DiffReport {
        operation,
        compared: shas.len(),
        left_header: lh,
        right_header: rh,
        mismatches,
    })
}
