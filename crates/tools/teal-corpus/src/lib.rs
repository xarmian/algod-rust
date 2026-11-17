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
//! Assembler input is any byte string, like go's `logic.AssembleString(string(body))`
//! (issue #2388). A diagnostic message that carries an invalid byte is written the
//! way go's `encoding/json` writes it: each such byte is one U+FFFD.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512_256};

/// Output schema version written to the header line.
pub const SCHEMA_VERSION: u32 = 1;

const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Default cap on workers hung past their timeout at once.
pub const DEFAULT_MAX_ABANDONED: usize = 64;

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
    /// Not serialized. `panic` records go's own panic text for an input on
    /// which go's assembler panics (a constant scratch index >= 256) and this
    /// port reports the same condition as a typed value, without panicking:
    /// the row is byte-identical to go's, and is not a robustness failure.
    #[serde(skip)]
    pub mirrors_go_panic: bool,
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
        Operation::Assemble => match algo_avm::assembler::assemble_bytes_checked(&input.bytes) {
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
                                message: go_json_message(&w.message_bytes()),
                            })
                            .collect(),
                    );
                }
            }
            Err(algo_avm::assembler::AssembleFailure::Panic(msg)) => {
                row.panic = Some(msg);
                row.mirrors_go_panic = true;
            }
            Err(algo_avm::assembler::AssembleFailure::Errors(errors)) => {
                row.errors = Some(
                    errors
                        .iter()
                        .map(|e| Diag {
                            col: e.col,
                            line: e.line,
                            message: go_json_message(&e.message_bytes()),
                        })
                        .collect(),
                );
            }
        },
    }
    row
}

/// A diagnostic message as go's `encoding/json` shows it (each byte that is not
/// part of a valid UTF-8 sequence is one U+FFFD).
fn go_json_message(bytes: &[u8]) -> String {
    algo_avm::raw_text::go_lossy(bytes)
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

/// Knobs of [`run_batch_with`].
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Parallel workers (one long-lived thread each).
    pub jobs: usize,
    /// Per-input time budget.
    pub timeout: Duration,
    /// Stack size of a worker thread.
    pub stack_bytes: usize,
    /// Most workers that may be hung past their timeout at once. Beyond it the
    /// remaining inputs are refused with a recorded row error instead of piling
    /// up unkillable threads.
    pub max_abandoned: usize,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            jobs: 1,
            timeout: Duration::from_secs(10),
            stack_bytes: WORKER_STACK_BYTES,
            max_abandoned: DEFAULT_MAX_ABANDONED,
        }
    }
}

type Handles = Vec<std::thread::JoinHandle<()>>;

/// What a job's supervisor sees of its worker.
#[derive(Default)]
struct SlotState {
    /// The input index the worker is running and when it started it.
    current: Option<(usize, Instant)>,
    /// Set by the supervisor when `current` overran its timeout: the worker
    /// drops that input's row and exits.
    abandoned: bool,
    /// Set by the worker as it exits, however it exits.
    exited: bool,
}

/// The state one worker shares with its supervisor.
#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
    /// Signalled only when the worker exits (never per input).
    exited: Condvar,
}

impl Slot {
    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Everything a worker thread needs; workers may outlive the batch (hung past
/// their timeout), so it is shared, not borrowed.
struct Shared<F> {
    f: F,
    inputs: Vec<Input>,
    next: AtomicUsize,
    results: Mutex<Vec<Row>>,
}

impl<F> Shared<F> {
    /// The next unclaimed input index, if any.
    fn claim(&self) -> Option<usize> {
        let i = self.next.fetch_add(1, Ordering::Relaxed);
        (i < self.inputs.len()).then_some(i)
    }

    fn push(&self, row: Row) {
        self.results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(row);
    }
}

/// Marks the slot exited and wakes the supervisor when the worker returns or
/// unwinds.
struct ExitGuard(Arc<Slot>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.lock().exited = true;
        self.0.exited.notify_all();
    }
}

/// A long-lived worker thread: it runs `first`, then claims inputs itself
/// until none are left, so there is no thread hand-off per input.
struct Worker {
    slot: Arc<Slot>,
    handle: std::thread::JoinHandle<()>,
}

fn spawn_worker<F>(shared: &Arc<Shared<F>>, first: usize, stack_bytes: usize) -> io::Result<Worker>
where
    F: Fn(&Input) -> Row + Send + Sync + 'static,
{
    let slot = Arc::new(Slot::default());
    let worker_slot = Arc::clone(&slot);
    let shared = Arc::clone(shared);
    let handle = std::thread::Builder::new()
        .stack_size(stack_bytes)
        .spawn(move || {
            let _exit = ExitGuard(Arc::clone(&worker_slot));
            let mut next = Some(first);
            while let Some(i) = next {
                worker_slot.lock().current = Some((i, Instant::now()));
                let input = &shared.inputs[i];
                let r =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (shared.f)(input)));
                {
                    let mut st = worker_slot.lock();
                    // The supervisor gave up on this input (timeout): exit.
                    if st.abandoned {
                        return;
                    }
                    st.current = None;
                }
                shared.push(match r {
                    Ok(row) => row,
                    Err(p) => failure_row(&input.sha256, Some(panic_message(&*p)), None),
                });
                next = shared.claim();
            }
        })?;
    Ok(Worker { slot, handle })
}

/// Workers whose input overran its timeout. They cannot be killed. Their
/// handles are kept (never dropped, which would `pthread_detach` a thread that
/// may be exiting, the glibc race of #2382): finished ones are joined, hung ones
/// are leaked at the end of the batch and die with the process.
#[derive(Default)]
struct Abandoned(Mutex<Handles>);

impl Abandoned {
    fn lock(&self) -> std::sync::MutexGuard<'_, Handles> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn reap(list: &mut Handles) {
        let mut hung = Vec::with_capacity(list.len());
        for h in list.drain(..) {
            if h.is_finished() {
                let _ = h.join();
            } else {
                hung.push(h);
            }
        }
        *list = hung;
    }

    fn add(&self, h: std::thread::JoinHandle<()>) {
        let mut list = self.lock();
        Self::reap(&mut list);
        list.push(h);
    }

    /// Number of abandoned workers still running.
    fn live(&self) -> usize {
        let mut list = self.lock();
        Self::reap(&mut list);
        list.len()
    }

    fn leak_rest(&self) {
        let mut list = self.lock();
        Self::reap(&mut list);
        for h in list.drain(..) {
            std::mem::forget(h);
        }
    }
}

fn failure_row(sha256: &str, panic: Option<String>, timeout: Option<bool>) -> Row {
    Row {
        ok: false,
        panic,
        sha256: sha256.to_string(),
        timeout,
        ..Row::default()
    }
}

/// Wait for `w` to exit, or for its current input to overrun `o.timeout` (the
/// worker is then abandoned). Wakes only at the running input's deadline and
/// when the worker exits.
fn supervise<F>(w: Worker, shared: &Shared<F>, o: &BatchOptions, abandoned: &Abandoned) {
    let mut st = w.slot.lock();
    loop {
        if st.exited {
            // A worker only exits with an input in hand when that input's
            // thread died outside `catch_unwind`.
            let lost = st.current.take();
            drop(st);
            let _ = w.handle.join();
            if let Some((i, _)) = lost {
                shared.push(failure_row(
                    &shared.inputs[i].sha256,
                    Some("worker thread vanished".to_string()),
                    None,
                ));
            }
            return;
        }
        let wait = match st.current {
            Some((i, started)) => {
                let elapsed = started.elapsed();
                if elapsed >= o.timeout {
                    st.abandoned = true;
                    drop(st);
                    shared.push(failure_row(&shared.inputs[i].sha256, None, Some(true)));
                    abandoned.add(w.handle);
                    return;
                }
                o.timeout - elapsed
            }
            // Between two inputs: the next one starts at once.
            None => o.timeout,
        };
        st = w
            .slot
            .exited
            .wait_timeout(st, wait)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

/// Run `f` over every input on `o.jobs` long-lived worker threads (each input
/// under `catch_unwind` with a per-input `o.timeout`). Rows come back sorted by
/// sha256, independent of scheduling.
///
/// One thread per job is reused for every input. (A thread per input, whose
/// `JoinHandle` was dropped, crashed with SIGSEGV on 200k+ input batches: glibc
/// unmaps a stack above its stack-cache size as the thread exits, and
/// `pthread_detach` on that exiting thread reads the unmapped descriptor, #2382.)
/// Each worker claims its own inputs and each job's supervisor sleeps until the
/// running input's deadline or the worker's exit, so no input pays a
/// cross-thread hand-off (issue #2411: two futex wake-ups per input were a
/// quarter of the disassemble batch). A worker that overruns its timeout is
/// abandoned and replaced, at most `o.max_abandoned` at a time; a failed spawn
/// and a refused input are recorded as row errors.
pub fn run_batch_with<F>(inputs: Vec<Input>, o: &BatchOptions, f: F) -> Vec<Row>
where
    F: Fn(&Input) -> Row + Send + Sync + 'static,
{
    let n = inputs.len();
    let shared = Arc::new(Shared {
        f,
        inputs,
        next: AtomicUsize::new(0),
        results: Mutex::new(Vec::with_capacity(n)),
    });
    let abandoned = Abandoned::default();
    std::thread::scope(|s| {
        for _ in 0..o.jobs.max(1).min(n.max(1)) {
            s.spawn(|| {
                while let Some(i) = shared.claim() {
                    let live = abandoned.live();
                    if live >= o.max_abandoned {
                        shared.push(failure_row(
                            &shared.inputs[i].sha256,
                            Some(format!(
                                "abandoned worker limit reached ({live} workers hung past the {:?} timeout); input not run",
                                o.timeout
                            )),
                            None,
                        ));
                        continue;
                    }
                    let w = match spawn_worker(&shared, i, o.stack_bytes) {
                        Ok(w) => w,
                        Err(e) => {
                            shared.push(failure_row(
                                &shared.inputs[i].sha256,
                                Some(format!("failed to spawn worker thread: {e}")),
                                None,
                            ));
                            continue;
                        }
                    };
                    // When the worker ran out of inputs the next claim fails too.
                    supervise(w, &shared, o, &abandoned);
                }
            });
        }
    });
    abandoned.leak_rest();
    let mut rows = std::mem::take(&mut *shared.results.lock().unwrap_or_else(|e| e.into_inner()));
    rows.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    rows
}

/// [`run_batch_with`] with the default stack and abandoned-worker limit.
pub fn run_batch<F>(inputs: Vec<Input>, jobs: usize, timeout: Duration, f: F) -> Vec<Row>
where
    F: Fn(&Input) -> Row + Send + Sync + 'static,
{
    let o = BatchOptions {
        jobs,
        timeout,
        ..BatchOptions::default()
    };
    run_batch_with(inputs, &o, f)
}

/// True when any row is a recorded panic or timeout.
pub fn has_robustness_failure(rows: &[Row]) -> bool {
    rows.iter()
        .any(|r| (r.panic.is_some() && !r.mirrors_go_panic) || r.timeout == Some(true))
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
    /// Rows equal on both sides that succeeded.
    pub identical: usize,
    /// Rows equal on both sides that failed with the same error (list).
    pub both_error_identical: usize,
    /// Rows, on either side, that record a panic or a timeout. These count as
    /// failures even when both sides agree.
    pub robustness_failures: usize,
    /// Rows equal on both sides that record the same panic (go's assembler
    /// panics and the port reports the identical typed condition, #2381).
    pub both_panic_identical: usize,
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

/// True for a `panic` row carrying go's assembler panic for a constant scratch
/// index >= 256 (`runtime error: index out of range [N] with length 256`),
/// the one panic the Rust assembler reproduces as a typed condition.
fn is_assembler_scratch_panic(row: &Value) -> bool {
    row.get("panic")
        .and_then(Value::as_str)
        .and_then(|m| m.strip_prefix("runtime error: index out of range ["))
        .and_then(|m| m.strip_suffix("] with length 256"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
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
    let (mut identical, mut both_error_identical) = (0, 0);
    let is_robustness_failure =
        |v: &Value| v.get("panic").is_some() || v.get("timeout") == Some(&Value::Bool(true));
    // A panic row that is byte-equal on both sides AND is go's assembler
    // scratch-index panic is parity (the port reports that panic as a typed
    // value, #2381); every other panic, one-sided or differing panics, and
    // every timeout are robustness failures.
    let mirrored = |sha: &String| match (lrows.get(sha), rrows.get(sha)) {
        (Some(a), Some(b)) => a == b && is_assembler_scratch_panic(a),
        _ => false,
    };
    let robustness_failures = lrows
        .iter()
        .chain(rrows.iter())
        .filter(|(sha, v)| is_robustness_failure(v) && !mirrored(sha))
        .count();
    let both_panic_identical = shas.iter().filter(|sha| mirrored(sha)).count();
    for sha in &shas {
        let (l, r) = (lrows.get(*sha), rrows.get(*sha));
        let (field, fd, lv, rv) = match (l, r) {
            (Some(a), Some(b)) if a == b => {
                if a.get("ok") == Some(&Value::Bool(true)) {
                    identical += 1;
                } else if !is_robustness_failure(a) && !is_assembler_scratch_panic(a) {
                    both_error_identical += 1;
                }
                continue;
            }
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
        identical,
        both_error_identical,
        robustness_failures,
        both_panic_identical,
        left_header: lh,
        right_header: rh,
        mismatches,
    })
}
