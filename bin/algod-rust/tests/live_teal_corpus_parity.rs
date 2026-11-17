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

//! Live dual-node REST-tier parity of the Phase 25 TEAL corpus (issue #2370,
//! epic #2364).
//!
//! The offline tier (`crates/tools/teal-corpus`, `tools/teal-corpus`) compares
//! the library functions over the whole ARC56Registry corpus. This test sends a
//! deterministic, seeded sample of the same corpus through the real handlers of
//! a go-algorand node and an algod-rust node (`EnableDeveloperAPI` on), so the
//! handler layer is covered too: JSON shape, `hash`, `result`, `sourcemap`,
//! status codes, error bodies, content type and the request-size limit.
//!
//! Per sampled program `P` (with original source `S` where the spec ships one):
//!
//! * `POST /v2/teal/disassemble` with `P`;
//! * `POST /v2/teal/compile` and `?sourcemap=true` with the TEAL `T` that go's
//!   disassembler returned, and with `S`.
//!
//! Every call is compared between the two nodes (status, content type, full
//! body bytes), and each node's answer is compared with the offline driver's
//! row for the same input (`teal_corpus::process`, the same library calls the
//! Rust handlers make). When `TEAL_CORPUS_GO_DRIVER` names the built
//! `tools/teal-corpus` binary, go's own offline rows are used for go's side as
//! well; without it go's REST answers are held against the Rust offline rows,
//! which the offline tier (#2367-#2369) proves equal to go's. The test also
//! covers the request-size boundary (the largest corpus program plus synthetic
//! bodies at and over `MaxTealSourceBytes`), a handful of handler edge cases
//! (including compile bodies that are not UTF-8, which go assembles: a literal
//! keeps its bytes and a failed compile's message carries `\ufffd`, #2388)
//! and the go assembler panic (a constant scratch index >= 256) that makes go
//! drop the connection (#2381): both nodes must give a transport error and keep
//! serving.
//!
//! Sample: the largest program and source, one program per AVM version present,
//! every program that errors in the offline tier, then a seeded shuffle of the
//! rest up to `SAMPLE` (default 300; `SAMPLE=all` for everything).
//!
//! Environment:
//!
//! * `TEAL_CORPUS_DIR` - corpus directory from `scripts/teal-corpus/extract.py`
//!   (default `<repo>/teal-corpus-work/corpus`);
//! * `SEED` (default 2370), `SAMPLE`;
//! * `ALGOD_GO_URL` / `ALGOD_RUST_URL` - the two nodes (defaults
//!   `http://127.0.0.1:4001` / `:4002`, the `make validate-api-up` harness);
//! * `TEAL_CORPUS_GO_DRIVER` - optional go offline driver;
//! * `TEAL_CORPUS_REST_OUT` - directory to write `rest_sample.{go,rust}.jsonl`
//!   into (one row per node-vs-node comparison; `scripts/teal-corpus/stats.py`
//!   turns them into the `rest_sample` stage of `stats.json`, #2372);
//! * `TEAL_CORPUS_REQUIRED=1` - fail instead of skipping when the corpus or a
//!   node is missing (CI sets it).
//!
//! ```text
//! make teal-corpus-fetch
//! make validate-api-up
//! cargo test --release -p algod-rust --test live_teal_corpus_parity -- --ignored --nocapture
//! make validate-api-down
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use teal_corpus::{Input, Operation};
use tokio::sync::Semaphore;

const DEV_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// go-algorand `MaxTealSourceBytes` (`daemon/algod/api/server/v2/handlers.go`).
const MAX_TEAL_SOURCE_BYTES: usize = 512 * 1024;

const DEFAULT_SEED: u64 = 2370;
const DEFAULT_SAMPLE: usize = 300;
const CONCURRENCY: usize = 8;

fn go_url() -> String {
    std::env::var("ALGOD_GO_URL").unwrap_or_else(|_| "http://127.0.0.1:4001".to_string())
}

fn rust_url() -> String {
    std::env::var("ALGOD_RUST_URL").unwrap_or_else(|_| "http://127.0.0.1:4002".to_string())
}

fn required() -> bool {
    std::env::var("TEAL_CORPUS_REQUIRED").is_ok_and(|v| v == "1")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Go,
    Rust,
}

impl Node {
    fn name(self) -> &'static str {
        match self {
            Node::Go => "go",
            Node::Rust => "rust",
        }
    }
    fn url(self) -> String {
        match self {
            Node::Go => go_url(),
            Node::Rust => rust_url(),
        }
    }
}

/// One HTTP answer: status, content type and the raw body.
#[derive(Clone, Debug)]
struct Resp {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

/// `Err` is a transport error (no HTTP response at all).
type HttpResult = Result<Resp, String>;

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(0)
        .build()
        .expect("build reqwest client")
}

async fn request(
    c: &reqwest::Client,
    node: Node,
    method: reqwest::Method,
    path: &str,
    body: Vec<u8>,
    token: Option<&str>,
) -> HttpResult {
    let mut req = c.request(method, format!("{}{}", node.url(), path));
    if let Some(t) = token {
        req = req.header("X-Algo-API-Token", t);
    }
    let resp = req.body(body).send().await.map_err(|e| format!("{e:?}"))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp.bytes().await.map_err(|e| format!("{e:?}"))?.to_vec();
    Ok(Resp {
        status,
        content_type,
        body,
    })
}

async fn post(c: &reqwest::Client, node: Node, path: &str, body: Vec<u8>) -> HttpResult {
    request(c, node, reqwest::Method::POST, path, body, Some(DEV_TOKEN)).await
}

fn show(r: &HttpResult) -> String {
    match r {
        Err(e) => format!("transport error: {e}"),
        Ok(r) => {
            let body = String::from_utf8_lossy(&r.body);
            let head: String = body.chars().take(120).collect();
            let tail: Vec<char> = body.chars().rev().take(40).collect();
            let tail: String = tail.into_iter().rev().collect();
            format!(
                "{} [{}] len={} {head:?} ... {tail:?}",
                r.status,
                r.content_type,
                r.body.len()
            )
        }
    }
}

/// splitmix64: a fixed, dependency-free generator so a seed reproduces the sample.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// One manifest entry of `scripts/teal-corpus/extract.py`.
#[derive(Clone, Debug)]
struct Entry {
    sha: String,
    size: u64,
    version: u64,
    source_sha: Option<String>,
}

fn load_manifest(dir: &Path) -> Vec<Entry> {
    let text = std::fs::read_to_string(dir.join("manifest.jsonl")).expect("read manifest.jsonl");
    let mut out: Vec<Entry> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).expect("manifest line");
            Entry {
                sha: v["sha256"].as_str().expect("sha256").to_string(),
                size: v["size"].as_u64().unwrap_or(0),
                version: v["version"].as_u64().unwrap_or(0),
                source_sha: v["source_sha256"].as_str().map(str::to_string),
            }
        })
        .collect();
    out.sort_by(|a, b| a.sha.cmp(&b.sha));
    out
}

fn read_program(dir: &Path, sha: &str) -> Vec<u8> {
    std::fs::read(dir.join("programs").join(format!("{sha}.bin"))).expect("read program")
}

fn read_source(dir: &Path, sha: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join("sources").join(format!("{sha}.teal"))).ok()
}

fn input_of(bytes: Vec<u8>) -> Input {
    Input {
        sha256: teal_corpus::sha256_hex(&bytes),
        bytes: Arc::new(bytes),
    }
}

/// Rows of the Rust offline driver keyed by input sha256, as JSON.
fn rust_offline(op: Operation, inputs: Vec<Input>) -> HashMap<String, Value> {
    let jobs = std::thread::available_parallelism().map_or(4, usize::from);
    teal_corpus::run_batch(inputs, jobs, Duration::from_secs(120), move |i| {
        teal_corpus::process(op, i)
    })
    .into_iter()
    .map(|r| (r.sha256.clone(), serde_json::to_value(&r).expect("row")))
    .collect()
}

/// Rows of go's offline driver (`TEAL_CORPUS_GO_DRIVER`) over `inputs`.
fn go_offline(
    driver: &Path,
    corpus: &Path,
    op: Operation,
    inputs: &[Input],
    scratch: &Path,
) -> HashMap<String, Value> {
    let dir = scratch.join(format!("go-in-{}", op.name()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create driver input dir");
    let ext = match op {
        Operation::Disassemble => "bin",
        Operation::Assemble => "teal",
    };
    for i in inputs {
        std::fs::write(dir.join(format!("{}.{ext}", i.sha256)), i.bytes.as_slice())
            .expect("write driver input");
    }
    let out = scratch.join(format!("go-out-{}.jsonl", op.name()));
    let status = std::process::Command::new(driver)
        .arg(op.name())
        .arg("--corpus")
        .arg(corpus)
        .arg("--input-dir")
        .arg(&dir)
        .arg("--out")
        .arg(&out)
        .status()
        .expect("run go driver");
    // 3 = a panic row was recorded (go's own scratch-index panic is expected).
    assert!(
        matches!(status.code(), Some(0) | Some(3)),
        "go driver {} failed: {status}",
        op.name()
    );
    std::fs::read_to_string(&out)
        .expect("read go driver output")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("header").is_none())
        .map(|v| (v["sha256"].as_str().expect("row sha").to_string(), v))
        .collect()
}

/// `(name, method, path, body, token)`.
type EdgeCase<'a> = (&'a str, reqwest::Method, &'a str, Vec<u8>, Option<&'a str>);

struct Mismatches(Vec<String>);

impl Mismatches {
    fn add(&mut self, m: String) {
        self.0.push(m);
    }
}

/// The `rest_sample` stage rows (#2372): one go row and one rust row per
/// node-vs-node comparison, in the driver JSONL row shape that
/// `scripts/teal-corpus/stats.py` aggregates. Equal answers (status, content
/// type, body bytes, or a transport error on both sides) give equal rows.
#[derive(Default)]
struct RestRows(Vec<(String, Value, Value)>);

fn rest_row(label: &str, r: &HttpResult) -> Value {
    let sha256 = teal_corpus::sha256_hex(label.as_bytes());
    match r {
        Ok(r) => serde_json::json!({
            "sha256": sha256,
            "ok": r.status == 200,
            "status": r.status,
            "content_type": r.content_type,
            "body_sha256": teal_corpus::sha256_hex(&r.body),
        }),
        Err(_) => serde_json::json!({"sha256": sha256, "ok": false, "error": "transport error"}),
    }
}

impl RestRows {
    fn add(&mut self, label: &str, go: &HttpResult, rust: &HttpResult) {
        self.0.push((
            label.to_string(),
            rest_row(label, go),
            rest_row(label, rust),
        ));
    }

    /// Write `rest_sample.{go,rust}.jsonl` into `dir` (`TEAL_CORPUS_REST_OUT`).
    fn write(&self, dir: &Path) {
        std::fs::create_dir_all(dir).expect("rest out dir");
        for (impl_name, pick) in [("go", 1usize), ("rust", 2usize)] {
            let mut text = serde_json::json!({"header": {
                "operation": "rest_sample", "impl": impl_name,
            }})
            .to_string();
            text.push('\n');
            for row in &self.0 {
                let v = if pick == 1 { &row.1 } else { &row.2 };
                text.push_str(&v.to_string());
                text.push('\n');
            }
            std::fs::write(dir.join(format!("rest_sample.{impl_name}.jsonl")), text)
                .expect("write rest_sample rows");
        }
    }
}

/// Compare the two nodes' answers to the same request: status, content type and
/// the full body bytes (a transport error on one side only is a mismatch).
fn compare_nodes(
    label: &str,
    go: &HttpResult,
    rust: &HttpResult,
    out: &mut Mismatches,
    rows: &mut RestRows,
) {
    rows.add(label, go, rust);
    let same = match (go, rust) {
        (Err(_), Err(_)) => true,
        (Ok(g), Ok(r)) => {
            g.status == r.status && g.content_type == r.content_type && g.body == r.body
        }
        _ => false,
    };
    if !same {
        out.add(format!(
            "{label}: node mismatch\n    go:   {}\n    rust: {}",
            show(go),
            show(rust)
        ));
    }
}

fn message_of(r: &Resp) -> Option<String> {
    let v: Value = serde_json::from_slice(&r.body).ok()?;
    v.get("message")?.as_str().map(str::to_string)
}

/// A node's `/v2/teal/disassemble` answer against the offline row.
fn check_disassemble(label: &str, node: Node, row: &Value, got: &HttpResult, out: &mut Mismatches) {
    let r = match got {
        Ok(r) => r,
        Err(e) => {
            out.add(format!(
                "{label}: {} offline/REST: transport error {e}",
                node.name()
            ));
            return;
        }
    };
    if row["ok"] == Value::Bool(true) {
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        if r.status != 200 || body["result"] != row["text"] {
            out.add(format!(
                "{label}: {} offline/REST: offline ok, REST {}",
                node.name(),
                show(got)
            ));
        }
    } else if r.status != 400 || message_of(r).as_deref() != row["error"].as_str() {
        out.add(format!(
            "{label}: {} offline/REST: offline error {:?}, REST {}",
            node.name(),
            row["error"],
            show(got)
        ));
    }
}

/// A node's `/v2/teal/compile` answer against the offline row.
fn check_compile(
    label: &str,
    node: Node,
    row: &Value,
    sourcemap: bool,
    got: &HttpResult,
    out: &mut Mismatches,
) {
    let who = node.name();
    if row.get("panic").is_some() {
        // go's assembler panics and no middleware recovers it: no HTTP response.
        if got.is_ok() {
            out.add(format!(
                "{label}: {who} offline/REST: offline panic, REST {}",
                show(got)
            ));
        }
        return;
    }
    let r = match got {
        Ok(r) => r,
        Err(e) => {
            out.add(format!("{label}: {who} offline/REST: transport error {e}"));
            return;
        }
    };
    if row["ok"] == Value::Bool(true) {
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let sm_ok = if sourcemap {
            body.get("sourcemap") == row.get("sourcemap")
        } else {
            body.get("sourcemap").is_none()
        };
        if r.status != 200
            || body["result"] != row["bytecode_b64"]
            || body["hash"] != row["hash"]
            || !sm_ok
        {
            out.add(format!(
                "{label}: {who} offline/REST: offline ok (hash {}), REST {}",
                row["hash"],
                show(got)
            ));
        }
    } else {
        let msg = message_of(r).unwrap_or_default();
        let mut at = 0usize;
        let mut in_order = r.status == 400;
        for e in row["errors"].as_array().into_iter().flatten().take(10) {
            let text = e["message"].as_str().unwrap_or("");
            match msg[at..].find(text) {
                Some(i) => at += i + text.len(),
                None => in_order = false,
            }
        }
        if !in_order {
            out.add(format!(
                "{label}: {who} offline/REST: offline errors {}, REST {}",
                row["errors"],
                show(got)
            ));
        }
    }
}

struct Config {
    dir: PathBuf,
    seed: u64,
    sample: Option<usize>,
}

fn config() -> Config {
    let dir = std::env::var("TEAL_CORPUS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../teal-corpus-work/corpus")
        });
    let seed = std::env::var("SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);
    let sample = match std::env::var("SAMPLE").ok().as_deref() {
        Some("all") => None,
        Some(n) => Some(n.parse().expect("SAMPLE must be a number or `all`")),
        None => Some(DEFAULT_SAMPLE),
    };
    Config { dir, seed, sample }
}

fn pick(
    chosen: &mut BTreeSet<String>,
    reasons: &mut BTreeMap<String, &'static str>,
    sha: &str,
    why: &'static str,
) {
    if chosen.insert(sha.to_string()) {
        reasons.insert(sha.to_string(), why);
    }
}

fn skip_or_fail(reason: &str) {
    if required() {
        panic!("TEAL_CORPUS_REQUIRED=1 but {reason}");
    }
    eprintln!("SKIP live_teal_corpus_parity: {reason}");
}

#[derive(Default)]
struct Stats(BTreeMap<&'static str, usize>);

impl Stats {
    fn bump(&mut self, k: &'static str) {
        *self.0.entry(k).or_default() += 1;
    }
}

/// Run `f` over `items` with bounded concurrency, preserving order.
async fn par<T, R, F, Fut>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = R> + Send + 'static,
{
    let f = Arc::new(f);
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut handles = Vec::new();
    for item in items {
        let f = f.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore");
            f(item).await
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        out.push(h.await.expect("task"));
    }
    out
}

async fn nodes_up(c: &reqwest::Client) -> bool {
    for node in [Node::Go, Node::Rust] {
        let r = request(
            c,
            node,
            reqwest::Method::GET,
            "/v2/status",
            Vec::new(),
            Some(DEV_TOKEN),
        )
        .await;
        if !matches!(r, Ok(ref r) if r.status == 200) {
            skip_or_fail(&format!(
                "{} node is not reachable at {}",
                node.name(),
                node.url()
            ));
            return false;
        }
    }
    true
}

#[tokio::test]
#[ignore = "needs `make teal-corpus-fetch` and the dual-node harness (`make validate-api-up`)"]
async fn teal_corpus_rest_matches_go_and_offline() {
    let cfg = config();
    if !cfg.dir.join("manifest.jsonl").is_file() {
        skip_or_fail(&format!(
            "no corpus at {} (run `make teal-corpus-fetch`)",
            cfg.dir.display()
        ));
        return;
    }
    let c = client();
    if !nodes_up(&c).await {
        return;
    }
    let go_driver = std::env::var("TEAL_CORPUS_GO_DRIVER")
        .ok()
        .map(PathBuf::from);

    let registry_sha = std::fs::read_to_string(cfg.dir.join("corpus.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v["registry_sha"].as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());

    // ---- sample selection -------------------------------------------------
    let manifest = load_manifest(&cfg.dir);
    let all_programs: Vec<Input> = manifest
        .iter()
        .map(|e| input_of(read_program(&cfg.dir, &e.sha)))
        .collect();
    let all_sources: Vec<Input> = manifest
        .iter()
        .filter_map(|e| {
            e.source_sha
                .as_deref()
                .and_then(|s| read_source(&cfg.dir, s))
        })
        .map(input_of)
        .collect();
    let disasm_all = rust_offline(Operation::Disassemble, all_programs);
    let asm_src_all = rust_offline(Operation::Assemble, all_sources);

    let mut chosen: BTreeSet<String> = BTreeSet::new();
    let mut reasons: BTreeMap<String, &'static str> = BTreeMap::new();
    if let Some(e) = manifest.iter().max_by_key(|e| e.size) {
        pick(&mut chosen, &mut reasons, &e.sha, "largest-program");
    }
    let largest_source = manifest
        .iter()
        .filter_map(|e| {
            let s = e.source_sha.as_deref()?;
            Some((read_source(&cfg.dir, s)?.len(), e))
        })
        .max_by_key(|(n, _)| *n);
    if let Some((_, e)) = largest_source {
        pick(&mut chosen, &mut reasons, &e.sha, "largest-source");
    }
    let mut by_version: BTreeMap<u64, &Entry> = BTreeMap::new();
    for e in &manifest {
        by_version.entry(e.version).or_insert(e);
    }
    for e in by_version.values() {
        pick(&mut chosen, &mut reasons, &e.sha, "version");
    }
    for e in &manifest {
        let program_errors = disasm_all
            .get(&e.sha)
            .is_some_and(|r| r["ok"] != Value::Bool(true));
        let source_errors = e
            .source_sha
            .as_deref()
            .and_then(|s| read_source(&cfg.dir, s))
            .map(|b| teal_corpus::sha256_hex(&b))
            .and_then(|h| asm_src_all.get(&h))
            .is_some_and(|r| r["ok"] != Value::Bool(true));
        if program_errors {
            pick(
                &mut chosen,
                &mut reasons,
                &e.sha,
                "offline-disassemble-error",
            );
        } else if source_errors {
            pick(&mut chosen, &mut reasons, &e.sha, "offline-assemble-error");
        }
    }
    let mut rest: Vec<&Entry> = manifest
        .iter()
        .filter(|e| !chosen.contains(&e.sha))
        .collect();
    let mut rng = SplitMix64(cfg.seed);
    for i in (1..rest.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        rest.swap(i, j);
    }
    let want = cfg.sample.unwrap_or(usize::MAX);
    for e in rest {
        if chosen.len() >= want {
            break;
        }
        pick(&mut chosen, &mut reasons, &e.sha, "seeded");
    }
    let sample: Vec<Entry> = manifest
        .iter()
        .filter(|e| chosen.contains(&e.sha))
        .cloned()
        .collect();
    let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
    for r in reasons.values() {
        *by_reason.entry(r).or_default() += 1;
    }
    println!(
        "teal-corpus REST tier: registry_sha={registry_sha} seed={} sample={}/{} ({by_reason:?}) go_driver={}",
        cfg.seed,
        sample.len(),
        manifest.len(),
        go_driver.is_some()
    );

    let scratch = std::env::temp_dir().join(format!("teal-corpus-rest-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    let mut mism = Mismatches(Vec::new());
    let mut rest_rows = RestRows::default();
    let mut stats = Stats::default();

    // ---- phase A: disassemble ---------------------------------------------
    let programs: Vec<(Entry, Arc<Vec<u8>>)> = sample
        .iter()
        .map(|e| (e.clone(), Arc::new(read_program(&cfg.dir, &e.sha))))
        .collect();
    let go_disasm: Option<HashMap<String, Value>> = go_driver.as_ref().map(|d| {
        let inputs: Vec<Input> = programs.iter().map(|(_, b)| input_of(b.to_vec())).collect();
        go_offline(d, &cfg.dir, Operation::Disassemble, &inputs, &scratch)
    });
    let c = Arc::new(c);
    let disasm_results = {
        let c = c.clone();
        par(programs.clone(), move |(e, bytes)| {
            let c = c.clone();
            async move {
                let go = post(&c, Node::Go, "/v2/teal/disassemble", bytes.to_vec()).await;
                let rust = post(&c, Node::Rust, "/v2/teal/disassemble", bytes.to_vec()).await;
                (e, go, rust)
            }
        })
        .await
    };
    let mut texts: Vec<(Entry, Vec<u8>)> = Vec::new();
    for (e, go, rust) in &disasm_results {
        let label = format!("disassemble {} (v{}, {} bytes)", e.sha, e.version, e.size);
        compare_nodes(&label, go, rust, &mut mism, &mut rest_rows);
        let sha = &e.sha;
        let rust_row = &disasm_all[sha];
        let go_row = go_disasm.as_ref().map_or(rust_row, |m| &m[sha]);
        check_disassemble(&label, Node::Go, go_row, go, &mut mism);
        check_disassemble(&label, Node::Rust, rust_row, rust, &mut mism);
        match go {
            Ok(r) if r.status == 200 => {
                stats.bump("disassemble-ok");
                let v: Value = serde_json::from_slice(&r.body).expect("disassemble json");
                texts.push((
                    e.clone(),
                    v["result"].as_str().expect("result").as_bytes().to_vec(),
                ));
            }
            _ => stats.bump("disassemble-error"),
        }
    }

    // ---- phase B: offline rows for the TEAL the compile calls will send ----
    struct Job {
        label: String,
        text: Arc<Vec<u8>>,
        sha: String,
    }
    let mut jobs: Vec<Job> = Vec::new();
    for (e, t) in &texts {
        jobs.push(Job {
            label: format!("compile(disassembly of {})", e.sha),
            text: Arc::new(t.clone()),
            sha: teal_corpus::sha256_hex(t),
        });
    }
    for e in &sample {
        if let Some(s) = e
            .source_sha
            .as_deref()
            .and_then(|s| read_source(&cfg.dir, s))
        {
            jobs.push(Job {
                label: format!("compile(source of {})", e.sha),
                sha: teal_corpus::sha256_hex(&s),
                text: Arc::new(s),
            });
        }
    }
    let asm_inputs: Vec<Input> = jobs.iter().map(|j| input_of(j.text.to_vec())).collect();
    let rust_asm = rust_offline(Operation::Assemble, asm_inputs.clone());
    let go_asm = go_driver
        .as_ref()
        .map(|d| go_offline(d, &cfg.dir, Operation::Assemble, &asm_inputs, &scratch));

    // ---- phase C: compile, with and without the source map -----------------
    let mut calls: Vec<(String, Arc<Vec<u8>>, String, bool)> = Vec::new();
    for j in &jobs {
        for sourcemap in [false, true] {
            calls.push((j.label.clone(), j.text.clone(), j.sha.clone(), sourcemap));
        }
    }
    let compile_results = {
        let c = c.clone();
        par(calls, move |(label, text, sha, sourcemap)| {
            let c = c.clone();
            async move {
                let path = if sourcemap {
                    "/v2/teal/compile?sourcemap=true"
                } else {
                    "/v2/teal/compile"
                };
                let go = post(&c, Node::Go, path, text.to_vec()).await;
                let rust = post(&c, Node::Rust, path, text.to_vec()).await;
                (label, sha, sourcemap, text.len(), go, rust)
            }
        })
        .await
    };
    for (label, sha, sourcemap, len, go, rust) in &compile_results {
        let label = format!("{label} sourcemap={sourcemap}");
        compare_nodes(&label, go, rust, &mut mism, &mut rest_rows);
        if *len > MAX_TEAL_SOURCE_BYTES {
            // Over `MaxTealSourceBytes` (the largest programs' disassembly): both
            // nodes must answer with go's `http.MaxBytesReader` error.
            for (node, got) in [(Node::Go, go), (Node::Rust, rust)] {
                let too_large = matches!(got, Ok(r) if r.status == 400
                    && message_of(r).as_deref() == Some("http: request body too large"));
                if !too_large {
                    mism.add(format!(
                        "{label}: {} over-limit: {}",
                        node.name(),
                        show(got)
                    ));
                }
            }
            stats.bump("compile-over-limit");
            continue;
        }
        let rust_row = &rust_asm[sha];
        let go_row = go_asm.as_ref().map_or(rust_row, |m| &m[sha]);
        check_compile(&label, Node::Go, go_row, *sourcemap, go, &mut mism);
        check_compile(&label, Node::Rust, rust_row, *sourcemap, rust, &mut mism);
        match (go, rust_row.get("panic")) {
            (Err(_), _) => stats.bump("compile-dropped-connection"),
            (Ok(r), _) if r.status == 200 => stats.bump("compile-ok"),
            _ => stats.bump("compile-error"),
        }
    }

    // ---- request-size boundary ---------------------------------------------
    let largest = manifest
        .iter()
        .max_by_key(|e| e.size)
        .expect("non-empty corpus");
    let largest_bytes = read_program(&cfg.dir, &largest.sha);
    let zeros = |n: usize| vec![0u8; n];
    let padded_source = |n: usize| {
        let mut s = b"#pragma version 8\nint 1\n".to_vec();
        while s.len() + 2 <= n {
            s.extend_from_slice(b"//");
            let take = (n - s.len()).min(60).saturating_sub(1);
            s.extend(std::iter::repeat_n(b'a', take));
            s.push(b'\n');
        }
        while s.len() < n {
            s.push(b'\n');
        }
        s
    };
    let boundary: Vec<(String, &str, Vec<u8>)> = vec![
        (
            "largest program".into(),
            "/v2/teal/disassemble",
            largest_bytes.clone(),
        ),
        (
            format!("{MAX_TEAL_SOURCE_BYTES}-byte body"),
            "/v2/teal/disassemble",
            zeros(MAX_TEAL_SOURCE_BYTES),
        ),
        (
            format!("{}-byte body", MAX_TEAL_SOURCE_BYTES + 1),
            "/v2/teal/disassemble",
            zeros(MAX_TEAL_SOURCE_BYTES + 1),
        ),
        (
            format!("{MAX_TEAL_SOURCE_BYTES}-byte source"),
            "/v2/teal/compile",
            padded_source(MAX_TEAL_SOURCE_BYTES),
        ),
        (
            format!("{}-byte source", MAX_TEAL_SOURCE_BYTES + 1),
            "/v2/teal/compile",
            padded_source(MAX_TEAL_SOURCE_BYTES + 1),
        ),
        (
            format!("{}-byte source with sourcemap", MAX_TEAL_SOURCE_BYTES + 1),
            "/v2/teal/compile?sourcemap=true",
            padded_source(MAX_TEAL_SOURCE_BYTES + 1),
        ),
        (
            format!("{}-byte body", 4 * MAX_TEAL_SOURCE_BYTES),
            "/v2/teal/compile",
            padded_source(4 * MAX_TEAL_SOURCE_BYTES),
        ),
    ];
    for (name, path, body) in boundary {
        let go = post(&c, Node::Go, path, body.clone()).await;
        let rust = post(&c, Node::Rust, path, body).await;
        stats.bump("boundary");
        compare_nodes(
            &format!("size boundary {path} {name}"),
            &go,
            &rust,
            &mut mism,
            &mut rest_rows,
        );
    }

    // ---- handler edge cases -------------------------------------------------
    let edge: Vec<EdgeCase> = vec![
        (
            "compile empty body",
            reqwest::Method::POST,
            "/v2/teal/compile",
            vec![],
            Some(DEV_TOKEN),
        ),
        (
            "disassemble empty body",
            reqwest::Method::POST,
            "/v2/teal/disassemble",
            vec![],
            Some(DEV_TOKEN),
        ),
        (
            "compile sourcemap=false",
            reqwest::Method::POST,
            "/v2/teal/compile?sourcemap=false",
            b"#pragma version 8\nint 1\n".to_vec(),
            Some(DEV_TOKEN),
        ),
        (
            "compile sourcemap=garbage",
            reqwest::Method::POST,
            "/v2/teal/compile?sourcemap=garbage",
            b"#pragma version 8\nint 1\n".to_vec(),
            Some(DEV_TOKEN),
        ),
        (
            "compile no token",
            reqwest::Method::POST,
            "/v2/teal/compile",
            b"#pragma version 8\nint 1\n".to_vec(),
            None,
        ),
        (
            "disassemble wrong token",
            reqwest::Method::POST,
            "/v2/teal/disassemble",
            vec![8, 0x81, 1],
            Some("wrong"),
        ),
        (
            "compile GET",
            reqwest::Method::GET,
            "/v2/teal/compile",
            vec![],
            Some(DEV_TOKEN),
        ),
        (
            "disassemble GET",
            reqwest::Method::GET,
            "/v2/teal/disassemble",
            vec![],
            Some(DEV_TOKEN),
        ),
        (
            "compile 11 errors",
            reqwest::Method::POST,
            "/v2/teal/compile",
            format!("#pragma version 8\n{}", "bogus\n".repeat(11)).into_bytes(),
            Some(DEV_TOKEN),
        ),
        (
            "compile 1 error",
            reqwest::Method::POST,
            "/v2/teal/compile",
            b"#pragma version 8\nbogus\n".to_vec(),
            Some(DEV_TOKEN),
        ),
    ];
    // go assembles any byte string (`logic.AssembleString(string(body))`): a
    // string literal keeps its bytes, a comment is ignored, and an invalid byte in
    // an error message is one `\ufffd` of the JSON body (#2388).
    let mut edge = edge;
    let non_utf8: &[(&'static str, &[u8])] = &[
        (
            "compile non-UTF-8 body",
            b"#pragma version 8\nbyte \"\xff\xfe\"\nint 1\n",
        ),
        (
            "compile non-UTF-8 comment",
            b"#pragma version 8\nint 1 // \xff\xfe\n",
        ),
        (
            "compile non-UTF-8 label",
            b"#pragma version 8\nint 1\n\xfe:\nint 1\n",
        ),
        (
            "compile non-UTF-8 sourcemap literal",
            b"#pragma version 8\nbyte \"\xc3\xa9\xe2\"\nint 1\n",
        ),
        (
            "compile private-use literal",
            b"#pragma version 8\nbyte \"\xf4\x8f\xbc\x80\xf4\x8f\xbf\xbf\"\nint 1\n",
        ),
        (
            "compile non-UTF-8 unknown opcode",
            b"#pragma version 8\nfoo\xff\nint 1\n",
        ),
        (
            "compile truncated sequence",
            b"#pragma version 8\nint 1\n\xe2\x82 \n",
        ),
        (
            "compile non-UTF-8 immediate",
            b"#pragma version 8\nint \xff\n",
        ),
        (
            "compile non-UTF-8 hex",
            b"#pragma version 8\nbyte 0x\xffab\n",
        ),
        (
            "compile non-UTF-8 macro name",
            b"#pragma version 8\n#define \xff 1\nint 1\n",
        ),
        (
            "compile private-use opcode",
            b"#pragma version 8\nfoo\xf4\x8f\xbc\x80\nint 1\n",
        ),
        ("compile only invalid bytes", b"\xff\xfe"),
        (
            "compile two non-UTF-8 errors",
            b"#pragma version 8\nfoo\xff\nbar\xfe\n",
        ),
    ];
    for (name, body) in non_utf8 {
        edge.push((
            *name,
            reqwest::Method::POST,
            "/v2/teal/compile",
            body.to_vec(),
            Some(DEV_TOKEN),
        ));
    }
    edge.push((
        "compile non-UTF-8 body with sourcemap",
        reqwest::Method::POST,
        "/v2/teal/compile?sourcemap=true",
        b"#pragma version 8\nbyte \"\xff\xfe\"\nint 1\n".to_vec(),
        Some(DEV_TOKEN),
    ));
    for (name, method, path, body, token) in edge {
        let go = request(&c, Node::Go, method.clone(), path, body.clone(), token).await;
        let rust = request(&c, Node::Rust, method, path, body, token).await;
        stats.bump("edge-case");
        compare_nodes(
            &format!("edge case: {name}"),
            &go,
            &rust,
            &mut mism,
            &mut rest_rows,
        );
    }

    // ---- go's assembler panic: both nodes drop the connection ---------------
    let panic_sources = [
        "#pragma version 14\nint 300\nbyte 0x\nstores\n",
        "#pragma version 14\nint 300\nloads\npop\nint 1\n",
    ];
    for src in panic_sources {
        for node in [Node::Go, Node::Rust] {
            let r = post(&c, node, "/v2/teal/compile", src.as_bytes().to_vec()).await;
            stats.bump("dropped-connection-probe");
            if r.is_ok() {
                mism.add(format!(
                    "dropped connection {src:?}: {} answered {}",
                    node.name(),
                    show(&r)
                ));
            }
        }
    }
    for node in [Node::Go, Node::Rust] {
        // The node survives: 255 is the last valid slot, and a fresh connection works.
        let r = post(
            &c,
            node,
            "/v2/teal/compile",
            b"#pragma version 14\nint 255\nbyte 0x\nstores\nint 1\n".to_vec(),
        )
        .await;
        if !matches!(r, Ok(ref r) if r.status == 200) {
            mism.add(format!(
                "{} did not survive the dropped connection: {}",
                node.name(),
                show(&r)
            ));
        }
    }

    let _ = std::fs::remove_dir_all(&scratch);
    // The stage rows are written before any mismatch panic, so a red run still
    // has them (the node comparisons above are what they record).
    if let Ok(dir) = std::env::var("TEAL_CORPUS_REST_OUT") {
        if !dir.is_empty() {
            rest_rows.write(Path::new(&dir));
        }
    }
    println!("teal-corpus REST tier stats: {:?}", stats.0);
    if !mism.0.is_empty() {
        // Group by the first line with sha256 tokens and byte counts removed,
        // so one class of mismatch is reported once with a few examples.
        let mut classes: BTreeMap<String, Vec<&String>> = BTreeMap::new();
        for m in &mism.0 {
            let first = m.lines().next().unwrap_or("");
            let class: Vec<&str> = first
                .split_whitespace()
                .filter(|t| !(t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())))
                .filter(|t| !t.starts_with('(') && !t.ends_with("bytes)"))
                .collect();
            classes.entry(class.join(" ")).or_default().push(m);
        }
        let mut report = String::new();
        for (class, items) in &classes {
            report.push_str(&format!("\n== {} x {class}\n", items.len()));
            for m in items.iter().take(2) {
                report.push_str(m);
                report.push('\n');
            }
        }
        panic!(
            "{} REST-tier mismatches in {} classes (registry_sha={registry_sha}, seed={}):{report}",
            mism.0.len(),
            classes.len(),
            cfg.seed
        );
    }
    println!("teal-corpus REST tier: zero mismatches");
}
