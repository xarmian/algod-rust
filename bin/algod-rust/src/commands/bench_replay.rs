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

//! `algod-rust bench replay-corpus`: offline replay of a workload block
//! corpus (`benchmarks/corpus`, issue #2104) through algod-rust's production
//! catchup path, for the `replay` bench tier (issue #2105, epic #2101).
//!
//! Nothing here is a benchmark-only shortcut. The ledger is opened and
//! seeded by the same functions `algod-rust participate` uses
//! ([`open_and_configure_participate_ledger`],
//! [`seed_ledger_from_genesis_str`]), and the blocks are fetched, checked
//! and applied by [`CatchupService::sync_range`], the catchup service's
//! periodic sync pass (`sync_pass_inner`): parallel fetch workers, then in
//! round order the certificate check, `contents_match_header` and
//! [`AgreementLedgerBridge`]'s `ensure_block` (store block + cert, apply,
//! commit). Only two pieces are the corpus's own:
//!
//! * [`CorpusBlockFetcher`] reads a block from `blocks.bin` instead of a
//!   peer, and turns it into a [`FetchedBlockCert`] the way the gossip
//!   fetcher does (production decoder, raw payset blobs,
//!   [`fetched_certificate`]).
//! * [`CorpusCatchupLedger`] delegates everything to the bridge except the
//!   certificate check of a **DevMode** corpus, whose certificates hold only
//!   the round and cannot be authenticated; go's replay harness
//!   (`benchmarks/go-replay`) makes exactly the same exception.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use algo_agreement::{Certificate, NoOpNetworkAdvancer};
use algo_bench::corpus::{self, Histogram};
use algo_bench::replay_state::{compare_with_corpus, compute_final_state, FinalState, KnownSet};
use algo_ledger::catchup_service::SyncExitReason;
use algo_ledger::{
    AgreementLedgerBridge, BlockFetcher, CatchupLedger, CatchupService, FetchError,
    FetchedBlockCert, SqliteLedger,
};
use algo_types::{Block, Round};
use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use tracing::info;

use crate::commands::participate::{
    fetched_certificate, open_and_configure_participate_ledger, resolve_resource_paths,
    seed_ledger_from_genesis_str,
};

/// Schema of the result document (shared with `benchmarks/go-replay`).
pub const RESULT_SCHEMA: &str = "bench-replay-run/v1";

/// Process exit status when the replayed state differs from `corpus.json`.
pub const EXIT_CORPUS_MISMATCH: i32 = 3;

/// `bench replay-corpus` arguments.
#[derive(Debug, Clone)]
pub struct ReplayCorpusArgs {
    /// Corpus directory (`benchmarks/corpus/<name>`).
    pub corpus: PathBuf,
    /// Fresh node data directory (created; must be empty or absent).
    pub data_dir: PathBuf,
    /// `config.json` for the node; default: the corpus's `node-config.json`.
    pub config: Option<PathBuf>,
    /// Replay only rounds `1..=N` (bisecting); default: the whole corpus.
    pub rounds: Option<u64>,
    /// Also write the digested final-state lines into this directory.
    pub dump_state: Option<PathBuf>,
}

/// Timings and resource use of the timed section (see the `replay` tier
/// section of `docs/BENCHMARK_COMPARISON.md` for exactly what is included).
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReplayMetrics {
    pub wall_s: f64,
    pub blocks: u64,
    /// Top-level plus inner txns.
    pub txns: u64,
    pub inner_txns: u64,
    pub blocks_per_s: f64,
    pub txns_per_s: f64,
    /// `VmHWM` from `/proc/self/status` (0 off Linux).
    pub peak_rss_bytes: u64,
    /// `getrusage(RUSAGE_SELF)` over the timed section (0 off Unix).
    pub cpu_user_s: f64,
    pub cpu_sys_s: f64,
    /// `/proc/self/io` `write_bytes` over the timed section; `None` where
    /// the kernel keeps no per-task I/O accounting.
    pub write_bytes: Option<u64>,
    /// Size of the data directory after the close.
    pub db_bytes: u64,
    /// Part of `wall_s` after the last block was committed (closing the
    /// ledger).
    pub flush_s: f64,
}

/// The `bench-replay-run/v1` result document.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayResult {
    pub schema: &'static str,
    #[serde(rename = "impl")]
    pub implementation: &'static str,
    pub corpus: String,
    pub rounds: u64,
    pub config: BTreeMap<String, serde_json::Value>,
    pub metrics: ReplayMetrics,
    pub final_state: FinalState,
    /// `None` for a prefix replay (`--rounds` below the corpus's last).
    pub corpus_match: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub corpus_mismatches: Vec<String>,
}

/// Serves corpus blocks to the catchup service like a peer would: one
/// `blocks.bin` record per fetch, read from the file on demand and decoded
/// into the [`FetchedBlockCert`] the gossip fetcher builds
/// (`participate::fetch_block_via_unicast_peers`).
pub struct CorpusBlockFetcher {
    file: Mutex<File>,
    /// `(offset, len)` of the payload of round `i`.
    index: Vec<(u64, u32)>,
    last: u64,
    /// The last fetch failure of a round the replay needs (the catchup
    /// service only logs those at debug level), for the error message.
    last_error: Mutex<Option<String>>,
}

impl CorpusBlockFetcher {
    fn read(&self, round: u64) -> std::io::Result<Vec<u8>> {
        let (off, len) = self.index[round as usize];
        let mut buf = vec![0u8; len as usize];
        let mut f = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("corpus file lock poisoned"))?;
        f.seek(SeekFrom::Start(off))?;
        f.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl CorpusBlockFetcher {
    /// The last recorded fetch failure, if any.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|e| e.clone())
    }

    fn fetch(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        let raw = self
            .read(round.0)
            .map_err(|e| FetchError::NetworkError(format!("blocks.bin round {round}: {e}")))?;
        let resp = algo_codec::decode_block_response(&raw)
            .map_err(|e| FetchError::NetworkError(format!("round {round}: {e}")))?;
        if resp.block.round != round {
            return Err(FetchError::NetworkError(format!(
                "asked for round {round}, got block {}",
                resp.block.round
            )));
        }
        let raw_payset_blobs = algo_codec::extract_raw_payset_blobs(&raw).ok();
        let cert = fetched_certificate(round, resp.cert);
        Ok(FetchedBlockCert {
            block: resp.block,
            cert,
            raw_payset_blobs,
        })
    }
}

impl BlockFetcher for CorpusBlockFetcher {
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
        // Past the last round is the normal end of a sync pass, not an error.
        if round.0 == 0 || round.0 > self.last || round.0 as usize >= self.index.len() {
            return Err(FetchError::NoBlockForRound { round });
        }
        let res = self.fetch(round);
        if let Err(e) = &res {
            if let Ok(mut last) = self.last_error.lock() {
                *last = Some(format!("round {round}: {e}"));
            }
        }
        res
    }
}

/// The catchup service's ledger for a corpus replay: the production
/// [`AgreementLedgerBridge`], except that a DevMode corpus's degenerate
/// certificates (round only, no votes) are accepted after checking exactly
/// that, since there is no quorum to authenticate.
pub struct CorpusCatchupLedger {
    inner: Arc<AgreementLedgerBridge>,
    devmode: bool,
    /// The last certificate-authentication failure: the catchup service only
    /// logs it (as a warning), so the replay keeps it for its own error.
    last_auth_error: Arc<LastAuthError>,
}

/// The last certificate-authentication failure of a replay: the round and the
/// reason. A later successful authentication clears it, and it is reported
/// only for the round the replay stalled at, so a stall with another cause
/// (a fetch failure, an apply failure) never points at certificates.
#[derive(Default)]
pub struct LastAuthError(Mutex<Option<(u64, String)>>);

impl LastAuthError {
    /// Record the outcome of authenticating `round`'s certificate.
    pub fn note(&self, round: u64, res: &Result<(), String>) {
        if let Ok(mut last) = self.0.lock() {
            *last = res.as_ref().err().map(|e| (round, e.clone()));
        }
    }

    /// `"; last authentication error: round N: ..."` if the last failure was
    /// for `stalled`, else the empty string.
    pub fn report(&self, stalled: u64) -> String {
        match self.0.lock().ok().and_then(|l| l.clone()) {
            Some((round, e)) if round == stalled => {
                format!("; last authentication error: round {round}: {e}")
            }
            _ => String::new(),
        }
    }
}

/// The only certificate a DevMode chain has: `{"rnd": r}`.
pub fn check_devmode_certificate(block: &Block, cert: &Certificate) -> Result<(), String> {
    if cert.round != block.round {
        return Err(format!(
            "certificate for round {} carries block {}",
            cert.round, block.round
        ));
    }
    if !cert.votes.is_empty() || !cert.equivocation_votes.is_empty() {
        return Err("DevMode corpus carries a certificate with votes".to_string());
    }
    Ok(())
}

impl CatchupLedger for CorpusCatchupLedger {
    fn next_round(&self) -> Round {
        CatchupLedger::next_round(&*self.inner)
    }
    fn ensure_block(&self, block: &Block, cert: &Certificate) {
        CatchupLedger::ensure_block(&*self.inner, block, cert)
    }
    fn round_is_not_supported(&self, round: Round) -> bool {
        self.inner.round_is_not_supported(round)
    }
    fn is_behind_committing_deltas(&self) -> bool {
        self.inner.is_behind_committing_deltas()
    }
    fn authenticate_block(&self, block: &Block, cert: &Certificate) -> Result<(), String> {
        let res = if self.devmode {
            check_devmode_certificate(block, cert)
        } else {
            self.inner.authenticate_block(block, cert)
        };
        self.last_auth_error.note(block.round.0, &res);
        res
    }
    fn apply_stall_retry_in(&self, next_round: Round) -> Option<Duration> {
        self.inner.apply_stall_retry_in(next_round)
    }
    fn apply_stall_failed_digest(&self) -> Option<algo_types::Digest> {
        self.inner.apply_stall_failed_digest()
    }
}

/// Resource use of this process so far.
#[derive(Debug, Clone, Copy, Default)]
struct ProcStats {
    peak_rss: u64,
    user_s: f64,
    sys_s: f64,
    write_bytes: Option<u64>,
}

/// `<key> <value> [kB]` from a `/proc` file, in bytes.
#[cfg(target_os = "linux")]
fn proc_field(path: &str, key: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().find(|l| l.starts_with(key))?;
    let mut it = line[key.len()..].split_whitespace();
    let v: u64 = it.next()?.parse().ok()?;
    Some(if it.next() == Some("kB") { v * 1024 } else { v })
}

fn proc_stats() -> ProcStats {
    #[allow(unused_mut)]
    let mut s = ProcStats::default();
    #[cfg(unix)]
    {
        // SAFETY: getrusage only writes the struct it is given.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } == 0 {
            s.user_s = ru.ru_utime.tv_sec as f64 + ru.ru_utime.tv_usec as f64 / 1e6;
            s.sys_s = ru.ru_stime.tv_sec as f64 + ru.ru_stime.tv_usec as f64 / 1e6;
        }
    }
    #[cfg(target_os = "linux")]
    {
        s.peak_rss = proc_field("/proc/self/status", "VmHWM:").unwrap_or(0);
        s.write_bytes = proc_field("/proc/self/io", "write_bytes:");
    }
    s
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// What the untimed pre-pass learns from the corpus.
struct Prepass {
    index: Vec<(u64, u32)>,
    blocks: u64,
    txns: u64,
    inner: u64,
    known: Vec<algo_types::Address>,
    block0: Block,
}

/// Decode every record once (untimed): index `blocks.bin`, count the work
/// and collect `corpus.json`'s account set.
fn prepass(
    blocks_path: &Path,
    last: u64,
    genesis: &algo_ledger::genesis::GenesisJson,
) -> anyhow::Result<Prepass> {
    // Streamed, one record at a time: holding the whole file would inflate
    // the process's peak RSS (VmHWM is a lifetime peak).
    let mut r = std::io::BufReader::with_capacity(
        1 << 20,
        File::open(blocks_path).with_context(|| format!("opening {}", blocks_path.display()))?,
    );
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != corpus::BLOCKS_MAGIC {
        bail!("{}: bad magic", blocks_path.display());
    }
    let mut offset = magic.len() as u64;
    let mut index = Vec::with_capacity(last as usize + 1);
    let mut hist = Histogram::default();
    let mut known = KnownSet::new(genesis).map_err(|e| anyhow!(e))?;
    let mut txns = 0u64;
    let mut block0 = None;
    let mut payload = Vec::new();
    for i in 0..=last {
        let mut hdr = [0u8; 12];
        r.read_exact(&mut hdr)
            .with_context(|| format!("blocks.bin ends before round {i}"))?;
        let round = u64::from_be_bytes(hdr[..8].try_into().expect("8 bytes"));
        let len = u32::from_be_bytes(hdr[8..].try_into().expect("4 bytes"));
        if round != i {
            bail!("blocks.bin record {i} holds round {round}");
        }
        payload.resize(len as usize, 0);
        r.read_exact(&mut payload)
            .with_context(|| format!("blocks.bin: record for round {i} truncated"))?;
        index.push((offset + 12, len));
        offset += 12 + u64::from(len);
        let block = algo_codec::decode_block_response(&payload)
            .with_context(|| format!("round {i}: decoding"))?
            .block;
        if i == 0 {
            block0 = Some(block);
            continue;
        }
        hist.add_block(&block.payset);
        known.add_block(&block);
        txns += block.payset.len() as u64;
    }
    Ok(Prepass {
        index,
        blocks: last,
        txns,
        inner: hist.features.get("inner_txns").copied().unwrap_or(0),
        known: known.addresses().to_vec(),
        block0: block0.ok_or_else(|| anyhow!("blocks.bin has no round 0"))?,
    })
}

/// Replay the corpus; see the module docs.
pub fn replay_corpus(args: &ReplayCorpusArgs) -> anyhow::Result<ReplayResult> {
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(args.corpus.join("corpus.json")).context("reading corpus.json")?,
    )
    .context("parsing corpus.json")?;
    if meta["schema"] != "algod-corpus/v1" {
        bail!(
            "corpus.json: schema {}, want algod-corpus/v1",
            meta["schema"]
        );
    }
    let file = |k: &str| -> anyhow::Result<PathBuf> {
        let name = meta["files"][k]
            .as_str()
            .ok_or_else(|| anyhow!("corpus.json: files.{k} missing"))?;
        Ok(args.corpus.join(name))
    };
    let corpus_last = meta["rounds"]["last"]
        .as_u64()
        .ok_or_else(|| anyhow!("corpus.json: rounds.last missing"))?;
    let last = match args.rounds {
        Some(n) if n > corpus_last => {
            bail!("--rounds {n} beyond the corpus's last round {corpus_last}")
        }
        Some(0) => bail!("--rounds must be >= 1"),
        Some(n) => n,
        None => corpus_last,
    };

    let genesis_str =
        std::fs::read_to_string(file("genesis")?).context("reading the corpus genesis")?;
    let genesis = algo_ledger::parse_genesis_json(&genesis_str).map_err(|e| anyhow!("{e}"))?;
    let gh = data_encoding::BASE64.encode(&algo_ledger::genesis::genesis_hash(&genesis));
    if meta["network"]["genesis_hash"].as_str() != Some(gh.as_str()) {
        bail!("genesis.json hash {gh} does not match corpus.json");
    }
    let genesis_id = format!("{}-{}", genesis.network, genesis.id);

    // A node data directory: config.json in it, like a node's.
    if std::fs::read_dir(&args.data_dir).is_ok_and(|mut d| d.next().is_some()) {
        bail!(
            "{} is not empty: the replay needs a fresh ledger",
            args.data_dir.display()
        );
    }
    std::fs::create_dir_all(&args.data_dir)?;
    let cfg_src = match &args.config {
        Some(p) => p.clone(),
        None => file("node_config")?,
    };
    std::fs::copy(&cfg_src, args.data_dir.join("config.json"))
        .with_context(|| format!("copying {}", cfg_src.display()))?;
    let node_config = algo_config::Local::load_from_data_dir(&args.data_dir)
        .map_err(|e| anyhow!("config.json: {e}"))?;
    crate::falcon_backend::apply_falcon_backend(&node_config)?;

    let blocks_path = file("blocks")?;
    let pre = prepass(&blocks_path, last, &genesis)?;

    // participate's ledger open + genesis seed, then node.rs's devmode flag.
    let ledger_path = args.data_dir.join(&genesis_id).join("ledger");
    let resolved = resolve_resource_paths(&ledger_path, &node_config);
    for dir in [resolved.tracker_path.parent(), resolved.block_path.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir)?;
    }
    let open = || -> anyhow::Result<SqliteLedger> {
        let mut l = open_and_configure_participate_ledger(&ledger_path, &resolved, &node_config)?;
        // A go devmode chain's blocks have no proposer (issue #1803), as
        // `algod-rust node` sets for a devmode genesis.
        l.set_devmode_chain(genesis.devmode);
        Ok(l)
    };
    let mut ledger = open()?;
    seed_ledger_from_genesis_str(&mut ledger, &genesis_str, "corpus genesis.json", 0)?;
    {
        use algo_ledger::LedgerStore as _;
        let hdr = ledger
            .get_block_header_data(0)?
            .ok_or_else(|| anyhow!("no genesis block after seeding"))?;
        let ours = algo_codec::canonical_encode_block_header_from_block(&pre.block0);
        if hdr != ours {
            bail!("algod-rust's genesis block differs from the corpus's round 0 block");
        }
    }

    let corpus_fetcher = Arc::new(CorpusBlockFetcher {
        file: Mutex::new(File::open(&blocks_path)?),
        index: pre.index.clone(),
        last,
        last_error: Mutex::new(None),
    });
    let fetcher: Arc<dyn BlockFetcher> = corpus_fetcher.clone();
    let parallel = node_config.catchup_parallel_blocks;

    let before = proc_stats();
    let start = Instant::now();
    let shared = Arc::new(Mutex::new(ledger));
    let last_auth_error = Arc::new(LastAuthError::default());
    {
        let bridge = Arc::new(AgreementLedgerBridge::new_with_advancer_and_condvar(
            Arc::clone(&shared),
            Arc::new(NoOpNetworkAdvancer),
            Arc::new(Condvar::new()),
        ));
        let catchup: Arc<dyn CatchupLedger> = Arc::new(CorpusCatchupLedger {
            inner: bridge,
            devmode: genesis.devmode,
            last_auth_error: Arc::clone(&last_auth_error),
        });
        let (_stop_tx, stop_rx) = crossbeam_channel::bounded::<()>(1);
        loop {
            let next = catchup.next_round().0;
            if next > last {
                break;
            }
            let reason = CatchupService::sync_range(&catchup, &fetcher, &stop_rx, parallel);
            if catchup.next_round().0 == next {
                let fetch = corpus_fetcher
                    .last_error()
                    .map(|e| format!("; last fetch error: {e}"))
                    .unwrap_or_default();
                let auth = last_auth_error.report(next);
                bail!(
                    "replay stopped at round {next}: the catchup sync pass ended ({}) \
                     without committing it{fetch}{auth}",
                    exit_reason_str(&reason)
                );
            }
        }
    }
    let applied = Instant::now();
    // Close: every bridge is gone, so this is the last reference.
    match Arc::try_unwrap(shared) {
        Ok(m) => drop(
            m.into_inner()
                .map_err(|_| anyhow!("ledger lock poisoned"))?,
        ),
        // Something still holds the ledger, so it was not closed inside the
        // timed section and the measurement would be wrong.
        Err(_) => bail!("ledger still shared after the replay; it could not be closed"),
    }
    let end = Instant::now();
    let after = proc_stats();
    let wall = end.duration_since(start).as_secs_f64();

    let txns = pre.txns + pre.inner;
    let metrics = ReplayMetrics {
        wall_s: wall,
        blocks: pre.blocks,
        txns,
        inner_txns: pre.inner,
        blocks_per_s: pre.blocks as f64 / wall,
        txns_per_s: txns as f64 / wall,
        peak_rss_bytes: after.peak_rss,
        cpu_user_s: after.user_s - before.user_s,
        cpu_sys_s: after.sys_s - before.sys_s,
        write_bytes: match (before.write_bytes, after.write_bytes) {
            (Some(b), Some(a)) => Some(a.saturating_sub(b)),
            _ => None,
        },
        db_bytes: dir_size(&args.data_dir),
        flush_s: end.duration_since(applied).as_secs_f64(),
    };

    // The final state comes from the reopened ledger (untimed), like go's.
    let ledger = open()?;
    let final_state = compute_final_state(
        &ledger,
        &resolved.tracker_path,
        &pre.known,
        args.dump_state.as_deref(),
    )
    .map_err(|e| anyhow!("final state: {e}"))?;
    drop(ledger);

    let (corpus_match, corpus_mismatches) = if last == corpus_last {
        let mm = compare_with_corpus(&final_state, &meta["final_state"]);
        (Some(mm.is_empty()), mm)
    } else {
        (None, Vec::new())
    };
    let config = BTreeMap::from([
        ("Archival".into(), node_config.archival.into()),
        (
            "CatchupBlockValidateMode".into(),
            node_config.catchup_block_validate_mode.into(),
        ),
        ("CatchupParallelBlocks".into(), parallel.into()),
        (
            "MaxAcctLookback".into(),
            node_config.max_acct_lookback.into(),
        ),
        (
            "LedgerSynchronousMode".into(),
            node_config.ledger_synchronous_mode.into(),
        ),
        (
            "StorageEngine".into(),
            node_config.storage_engine.clone().into(),
        ),
        (
            "CatchpointInterval".into(),
            node_config.catchpoint_interval.into(),
        ),
        (
            "CatchpointTracking".into(),
            node_config.catchpoint_tracking.into(),
        ),
        ("DevMode".into(), genesis.devmode.into()),
    ]);
    Ok(ReplayResult {
        schema: RESULT_SCHEMA,
        implementation: "rust",
        corpus: meta["name"].as_str().unwrap_or("").to_string(),
        rounds: last,
        config,
        metrics,
        final_state,
        corpus_match,
        corpus_mismatches,
    })
}

fn exit_reason_str(r: &SyncExitReason) -> String {
    format!("{r:?}")
}

/// The CLI command: replay, write the result JSON, exit 3 when the state
/// differs from `corpus.json`.
pub fn run_replay_corpus(args: &ReplayCorpusArgs, out: &Path) -> anyhow::Result<()> {
    let res = replay_corpus(args)?;
    let m = &res.metrics;
    info!(
        blocks = m.blocks,
        txns = m.txns,
        wall_s = m.wall_s,
        "corpus replay done"
    );
    eprintln!(
        "algod-rust replay-corpus: {} blocks, {} txns ({} inner) in {:.2}s: {:.1} blocks/s, {:.0} txn/s; final round {} {}",
        m.blocks,
        m.txns,
        m.inner_txns,
        m.wall_s,
        m.blocks_per_s,
        m.txns_per_s,
        res.final_state.round,
        res.final_state.block_hash
    );
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = serde_json::to_string_pretty(&res)?;
    text.push('\n');
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    if res.corpus_match == Some(false) {
        for m in &res.corpus_mismatches {
            eprintln!("algod-rust replay-corpus: final state differs from corpus.json: {m}");
        }
        std::process::exit(EXIT_CORPUS_MISMATCH);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_corpus() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/corpus/small")
    }

    /// The small corpus replays through the production catchup path to
    /// exactly the state go-algorand reported (corpus.json) and the full
    /// state the go replay harness recorded
    /// (benchmarks/go-replay/testdata/small-final-state.json).
    #[test]
    fn small_corpus_replays_to_the_go_final_state() {
        let tmp = tempfile::tempdir().unwrap();
        let res = replay_corpus(&ReplayCorpusArgs {
            corpus: small_corpus(),
            data_dir: tmp.path().join("node"),
            config: None,
            rounds: None,
            dump_state: None,
        })
        .unwrap();
        assert_eq!(
            res.corpus_mismatches,
            Vec::<String>::new(),
            "differs from corpus.json"
        );
        assert_eq!(res.corpus_match, Some(true));
        assert_eq!(res.metrics.blocks, 2000);
        let recorded: FinalState = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../benchmarks/go-replay/testdata/small-final-state.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            res.final_state, recorded,
            "Rust replay final state != the go-recorded one"
        );
    }

    /// A corrupted txn (one byte of a note flipped) breaks the block's
    /// payset commitment: the catchup path refuses the block and the replay
    /// fails at that round instead of producing a state.
    #[test]
    fn corrupted_txn_fails_the_replay() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("corpus");
        std::fs::create_dir(&bad).unwrap();
        for e in std::fs::read_dir(small_corpus()).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), bad.join(e.file_name())).unwrap();
        }
        let round = corrupt_first_note(&bad.join("blocks.bin"), 7);
        let err = replay_corpus(&ReplayCorpusArgs {
            corpus: bad,
            data_dir: tmp.path().join("node"),
            config: None,
            rounds: None,
            dump_state: None,
        })
        .expect_err("a corrupted block must fail the replay");
        assert!(
            err.to_string()
                .contains(&format!("replay stopped at round {round}")),
            "{err}"
        );
    }

    /// A fetch failure (here: a record that no longer decodes, e.g. the file
    /// changed after the pre-pass) is kept for the "replay stopped" error,
    /// since the catchup service only logs it at debug level. Rounds past
    /// the replay's end are the normal end of a pass and are not recorded.
    #[test]
    fn fetcher_records_the_last_fetch_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("blocks.bin");
        std::fs::write(&path, [0xc1u8, 0xc1, 0xc1, 0xc1]).unwrap();
        let f = CorpusBlockFetcher {
            file: Mutex::new(File::open(&path).unwrap()),
            index: vec![(0, 0), (0, 4)],
            last: 1,
            last_error: Mutex::new(None),
        };
        assert!(f.fetch_block(Round(2)).is_err());
        assert_eq!(f.last_error(), None, "past the end is not an error");
        assert!(f.fetch_block(Round(1)).is_err());
        let e = f.last_error().expect("recorded");
        assert!(e.starts_with("round 1:"), "{e}");
    }

    /// Flip the last byte of the first txn note (`"bc" || u64`) in the first
    /// round >= `from` that has a txn; returns that round.
    fn corrupt_first_note(path: &Path, from: u64) -> u64 {
        let mut bytes = std::fs::read(path).unwrap();
        let recs: Vec<(u64, usize, usize)> = corpus::parse_blocks(&bytes)
            .unwrap()
            .iter()
            .map(|r| {
                let off = r.payload.as_ptr() as usize - bytes.as_ptr() as usize;
                (r.round, off, r.payload.len())
            })
            .collect();
        for (round, off, len) in recs {
            if round < from {
                continue;
            }
            // msgpack: "note" key (fixstr 4) then bin8 of 10 bytes.
            let payload = &bytes[off..off + len];
            if let Some(i) = payload
                .windows(7)
                .position(|w| w == [0xa4, b'n', b'o', b't', b'e', 0xc4, 10])
            {
                bytes[off + i + 7 + 9] ^= 0x01;
                std::fs::write(path, &bytes).unwrap();
                return round;
            }
        }
        panic!("no txn note found");
    }

    fn testnet_prefix() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/corpus/testnet-prefix50")
    }

    fn copy_corpus(src: &Path, dst: &Path) {
        std::fs::create_dir(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
        }
    }

    /// The one-time signatures (`cert.vote[*].sig.s`) of a record's
    /// certificate, from the production block-response decoder.
    fn vote_signatures(payload: &[u8]) -> Vec<Vec<u8>> {
        fn get<'a>(v: &'a rmpv::Value, key: &str) -> &'a rmpv::Value {
            v.as_map()
                .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some(key)))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("no `{key}` in the certificate"))
        }
        let resp = algo_codec::decode_block_response(payload).unwrap();
        let cert = resp.cert.expect("a certificate");
        get(&cert, "vote")
            .as_array()
            .expect("votes")
            .iter()
            .map(|vote| match get(get(vote, "sig"), "s") {
                rmpv::Value::Binary(b) => b.clone(),
                other => panic!("sig.s is {other:?}"),
            })
            .collect()
    }

    /// Flip the last byte of the ephemeral signature (`"s"`, bin8 of 64
    /// bytes) of the last vote in round `round`'s certificate. The key is
    /// searched only in that record, last occurrence (the certificate follows
    /// the block), and the decoded certificate before and after must differ
    /// in that signature's last byte and nowhere else.
    fn corrupt_last_vote_signature(path: &Path, round: u64) {
        let mut bytes = std::fs::read(path).unwrap();
        let (off, len) = corpus::parse_blocks(&bytes)
            .unwrap()
            .iter()
            .find(|r| r.round == round)
            .map(|r| {
                (
                    r.payload.as_ptr() as usize - bytes.as_ptr() as usize,
                    r.payload.len(),
                )
            })
            .expect("round in corpus");
        let before = vote_signatures(&bytes[off..off + len]);
        let i = bytes[off..off + len]
            .windows(4)
            .rposition(|w| w == [0xa1, b's', 0xc4, 64])
            .expect("a vote signature in the certificate");
        bytes[off + i + 4 + 63] ^= 0x01;
        let after = vote_signatures(&bytes[off..off + len]);
        assert!(!before.is_empty());
        let n = before.len();
        assert_eq!(before[..n - 1], after[..n - 1], "another vote changed");
        assert_eq!(before[n - 1][..63], after[n - 1][..63]);
        assert_eq!(before[n - 1][63] ^ after[n - 1][63], 1);
        std::fs::write(path, &bytes).unwrap();
    }

    /// The testnet prefix has real certificates (votes), so the replay runs
    /// the non-DevMode branch: every certificate goes through
    /// `AgreementLedgerBridge::authenticate_block`, and the state reached is
    /// the one go-algorand's ledger reached (benchmarks/corpus/testnet-prefix50).
    #[test]
    fn testnet_prefix_authenticates_every_certificate() {
        let tmp = tempfile::tempdir().unwrap();
        let res = replay_corpus(&ReplayCorpusArgs {
            corpus: testnet_prefix(),
            data_dir: tmp.path().join("node"),
            config: None,
            rounds: None,
            dump_state: None,
        })
        .unwrap();
        assert_eq!(res.corpus_mismatches, Vec::<String>::new());
        assert_eq!(res.corpus_match, Some(true));
        assert_eq!(res.metrics.blocks, 50);
        assert_eq!(
            res.config.get("DevMode"),
            Some(&serde_json::Value::Bool(false))
        );
    }

    /// Issue #2159: the 49 real go-produced certificates of the testnet
    /// prefix decode into `Certificate`s whose step is `cert`, and each
    /// re-encodes byte-identically to the stored certificate (so serving
    /// them back can never differ from go). Authentication of the same
    /// certificates is proven by `testnet_prefix_authenticates_every_certificate`.
    #[test]
    fn testnet_prefix_real_certificates_keep_step_and_round_trip() {
        let bytes = std::fs::read(testnet_prefix().join("blocks.bin")).unwrap();
        let mut checked = 0;
        for rec in corpus::parse_blocks(&bytes).unwrap() {
            let resp = algo_codec::decode_block_response(rec.payload).unwrap();
            let Some(cert_val) = resp.cert else { continue };
            let mut want = Vec::new();
            rmpv::encode::write_value(&mut want, &cert_val).unwrap();
            if want == [0x80] {
                continue; // the genesis block's empty certificate
            }
            let cert = fetched_certificate(Round(rec.round), Some(cert_val)).expect("decodes");
            assert_eq!(cert.step, algo_agreement::CERT, "round {}", rec.round);
            assert_eq!(cert.to_canonical_bytes(), want, "round {}", rec.round);
            checked += 1;
        }
        assert_eq!(checked, 50);
    }

    /// A flipped bit in one vote's signature must fail the replay at that
    /// round (certificate authentication), not just at the end.
    #[test]
    fn testnet_prefix_tampered_vote_fails_authentication() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("corpus");
        copy_corpus(&testnet_prefix(), &bad);
        corrupt_last_vote_signature(&bad.join("blocks.bin"), 30);
        let err = replay_corpus(&ReplayCorpusArgs {
            corpus: bad,
            data_dir: tmp.path().join("node"),
            config: None,
            rounds: None,
            dump_state: None,
        })
        .expect_err("a tampered vote must fail the replay");
        let msg = err.to_string();
        assert!(msg.contains("replay stopped at round 30"), "{msg}");
        // and it says why: the certificate did not authenticate (the votes
        // are checked in order; the flipped one is the last)
        assert!(
            msg.contains("last authentication error: round 30: ")
                && msg.contains("failed verification"),
            "{msg}"
        );
    }

    /// The authentication failure is reported only for the round the replay
    /// stalled at, and only while no later authentication has succeeded:
    /// a later unrelated stall must not point at certificates.
    #[test]
    fn last_auth_error_is_reported_only_for_the_stalled_round() {
        let e = LastAuthError::default();
        assert_eq!(e.report(5), "", "nothing recorded yet");
        e.note(5, &Err("vote at index 3 failed verification".to_string()));
        assert_eq!(
            e.report(5),
            "; last authentication error: round 5: vote at index 3 failed verification"
        );
        assert_eq!(
            e.report(6),
            "",
            "another round stalled: not an auth failure"
        );
        // the same round authenticates on a later attempt: cleared
        e.note(5, &Ok(()));
        assert_eq!(e.report(5), "");
        // a failure, then later rounds succeed, then an unrelated stall
        e.note(7, &Err("bad".to_string()));
        e.note(8, &Ok(()));
        assert_eq!(e.report(7), "");
        assert_eq!(e.report(9), "");
        // a genuine failure after successes is still reported
        e.note(9, &Err("bad again".to_string()));
        assert_eq!(
            e.report(9),
            "; last authentication error: round 9: bad again"
        );
    }

    #[test]
    fn devmode_certificate_check() {
        let block = Block {
            round: Round(5),
            ..Block::default()
        };
        let cert = Certificate {
            round: Round(5),
            ..Certificate::default()
        };
        assert_eq!(check_devmode_certificate(&block, &cert), Ok(()));
        let wrong = Certificate {
            round: Round(6),
            ..Certificate::default()
        };
        assert!(check_devmode_certificate(&block, &wrong).is_err());
    }
}
