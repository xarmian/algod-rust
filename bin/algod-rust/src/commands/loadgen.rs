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

//! `algod-rust loadgen` — a sustained-rate transaction load generator.
//!
//! Built for the 6-node mixed-cluster stress benchmark (issue #100), where
//! `goal clerk send` in a shell loop tops out around 1 txn per block and
//! cannot express "hold 500 TPS for three minutes". The generator:
//!
//! - keeps a pool of pre-funded accounts and signs every transaction
//!   **offline** (no kmd round-trip in the hot path);
//! - paces submissions against a global token budget so the achieved rate is
//!   the *requested* rate, not "as fast as the box goes" — with a linear ramp
//!   from zero over `--ramp-secs`;
//! - round-robins submissions across every node in the cluster via
//!   `POST /v2/transactions`, so relays and participation nodes all take
//!   ingress load;
//! - optionally emits 16-transaction atomic groups instead of singletons;
//! - samples confirmation latency by polling
//!   `GET /v2/transactions/pending/{txid}` for every Nth submission.
//!
//! Everything lands in a structured JSON report consumed by
//! `docker/scripts/bench-stress.sh`.
//!
//! ## Why 0-amount self-payments by default
//!
//! Algorand has no per-account nonce; a transaction is deduplicated by its
//! txid, which commits to the note field. Varying the note therefore yields an
//! unbounded stream of distinct, always-valid transactions from a fixed
//! account set, and a 0-amount payment consumes only the fee — so a modest
//! warmup funding of each generator account sustains hundreds of thousands of
//! transactions without a balance-tracking feedback loop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, compute_group_id,
    compute_txn_id,
};
use algo_rest_client::{AlgodClient, SuggestedParams, TxId};
use algo_txn_pipeline::PaymentBuilder;
use algo_types::{Address, SignedTransaction};
use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Domain-separation prefix for transaction signatures
/// (`../go-algorand/protocol/hash.go`, `Transaction` = "TX").
const TX_PREFIX: &[u8] = b"TX";

/// How often the background task re-reads `/v2/transactions/params`. The
/// validity window we request is 1000 rounds wide, so this only needs to beat
/// the round rate by a comfortable margin.
const PARAMS_REFRESH: Duration = Duration::from_secs(3);

/// Scheduler tick. Small enough that a 1000 TPS target is dispatched in
/// batches of ~100 rather than one-per-second bursts, large enough that the
/// tick itself is not the bottleneck.
const TICK: Duration = Duration::from_millis(100);

// ───────────────────────── key file ─────────────────────────

/// One generator account: an Algorand address plus the 32-byte ed25519 seed
/// that controls it, hex-encoded.
///
/// This file holds **live private keys**. It is written 0600 on unix and is
/// only ever meant to hold throwaway private-network accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountKey {
    /// Checksummed base32 Algorand address.
    pub address: String,
    /// Hex-encoded 32-byte ed25519 seed.
    pub seed: String,
}

/// The on-disk key-file shape written by `loadgen gen-accounts` and read by
/// `loadgen run`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyFile {
    /// Generator accounts, in generation order.
    pub accounts: Vec<AccountKey>,
}

/// A decoded, ready-to-sign generator account.
#[derive(Debug)]
struct LoadAccount {
    address: Address,
    signing: SigningKey,
}

impl KeyFile {
    /// Decode every entry into a signing key, verifying that the recorded
    /// address really is the seed's public key (a mismatch means a hand-edited
    /// or corrupted file, and would produce transactions that fail signature
    /// verification at the node — a confusing way to learn about it).
    fn decode(&self) -> anyhow::Result<Vec<LoadAccount>> {
        if self.accounts.is_empty() {
            anyhow::bail!("key file contains no accounts");
        }
        self.accounts
            .iter()
            .map(|acct| {
                let raw = hex::decode(&acct.seed)
                    .map_err(|e| anyhow::anyhow!("account {}: bad seed hex: {e}", acct.address))?;
                let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "account {}: seed must be 32 bytes, got {}",
                        acct.address,
                        raw.len()
                    )
                })?;
                let signing = SigningKey::from_bytes(&seed);
                let derived = Address(signing.verifying_key().to_bytes());
                let declared = Address::from_algorand_string(&acct.address)
                    .map_err(|e| anyhow::anyhow!("account {}: bad address: {e}", acct.address))?;
                if derived != declared {
                    anyhow::bail!(
                        "account {} does not match its seed (derived {derived})",
                        acct.address
                    );
                }
                Ok(LoadAccount {
                    address: declared,
                    signing,
                })
            })
            .collect()
    }
}

/// Generate `count` fresh accounts and write them to `out` as JSON.
pub fn gen_accounts(count: usize, out: &Path) -> anyhow::Result<()> {
    gen_accounts_inner(count, false, out)
}

/// Like [`gen_accounts`], but with `--deterministic`: seeds are derived from
/// the sequential index `0..count` instead of OS randomness, mirroring
/// go-algorand's `shared/pingpong.deterministicAccounts`/`netgoal generate
/// --deterministic` (`makeKeyFromSeed`/`randomDeterministicAccounts`'s
/// seed construction: `binary.LittleEndian.PutUint64(seed[:], i)`, the rest
/// zero-filled). Reproducible across runs from the same `count`, unlike the
/// random path -- useful for scripted/CI load-test setups that need the
/// same funded addresses every time.
pub fn gen_accounts_deterministic(count: usize, out: &Path) -> anyhow::Result<()> {
    gen_accounts_inner(count, true, out)
}

/// A single deterministic account seed for index `i`, matching go's
/// `makeKeyFromSeed`/pingpong's per-index seed exactly:
/// `binary.LittleEndian.PutUint64(seed[:], i)` with the remaining 24 bytes
/// zero.
pub fn deterministic_seed(index: u64) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&index.to_le_bytes());
    seed
}

fn gen_accounts_inner(count: usize, deterministic: bool, out: &Path) -> anyhow::Result<()> {
    if count == 0 {
        anyhow::bail!("--count must be at least 1");
    }
    let mut rng = rand::rng();
    let mut accounts = Vec::with_capacity(count);
    for i in 0..count {
        let seed = if deterministic {
            deterministic_seed(i as u64)
        } else {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            seed
        };
        let signing = SigningKey::from_bytes(&seed);
        let address = Address(signing.verifying_key().to_bytes());
        accounts.push(AccountKey {
            address: address.to_algorand_string(),
            seed: hex::encode(seed),
        });
    }
    let file = KeyFile { accounts };
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_private(out, serde_json::to_string_pretty(&file)?.as_bytes())?;
    println!(
        "wrote {} generator account(s) to {}",
        file.accounts.len(),
        out.display()
    );
    for acct in &file.accounts {
        println!("{}", acct.address);
    }
    Ok(())
}

/// Write private-key material with a 0600 mode where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.flush()
}

// ───────────────────────── pacing math ─────────────────────────

/// Instantaneous target rate at `elapsed` seconds into the run: a linear ramp
/// from 0 to `target_tps` over `ramp_secs`, flat thereafter.
///
/// Kept separate from the scheduler so the ramp shape is unit-testable.
pub fn ramped_tps(target_tps: f64, ramp_secs: f64, elapsed: f64) -> f64 {
    if target_tps <= 0.0 {
        return 0.0;
    }
    if ramp_secs <= 0.0 || elapsed >= ramp_secs {
        return target_tps;
    }
    if elapsed <= 0.0 {
        return 0.0;
    }
    target_tps * (elapsed / ramp_secs)
}

/// Cumulative transactions that *should* have been dispatched by `elapsed`
/// seconds, i.e. the integral of [`ramped_tps`].
///
/// Driving the scheduler off the integral rather than a per-tick rate makes
/// the run self-correcting: a tick that was starved (blocked on a slow node,
/// descheduled by the OS) is made up on the next tick instead of silently
/// lowering the achieved rate.
pub fn scheduled_by(target_tps: f64, ramp_secs: f64, elapsed: f64) -> f64 {
    if target_tps <= 0.0 || elapsed <= 0.0 {
        return 0.0;
    }
    if ramp_secs <= 0.0 {
        return target_tps * elapsed;
    }
    if elapsed < ramp_secs {
        // ∫₀ᵗ target * (s / ramp) ds = target * t² / (2 * ramp)
        target_tps * elapsed * elapsed / (2.0 * ramp_secs)
    } else {
        // Full ramp triangle plus the flat remainder.
        target_tps * ramp_secs / 2.0 + target_tps * (elapsed - ramp_secs)
    }
}

/// Nearest-rank percentile over an ascending-sorted slice. Returns 0 for an
/// empty sample so the report always carries a number.
pub fn percentile(sorted_ascending: &[u64], p: f64) -> u64 {
    if sorted_ascending.is_empty() {
        return 0;
    }
    let rank = (p / 100.0 * sorted_ascending.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted_ascending.len() - 1);
    sorted_ascending[idx]
}

// ───────────────────────── signing ─────────────────────────

/// Sign a transaction body, producing a submittable [`SignedTransaction`].
///
/// The signed message is `"TX" || canonical_encode(txn)` — see
/// `algo_validate::signature::verify_transaction_signature`, which is the
/// check this must satisfy on the receiving node.
pub fn sign_txn(signing: &SigningKey, txn: algo_types::Transaction) -> SignedTransaction {
    let canonical = canonical_encode_transaction(&txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);
    let sig = signing.sign(&msg).to_bytes();
    SignedTransaction {
        txn,
        sig,
        ..Default::default()
    }
}

// ───────────────────── fixed-count (deterministic) mode ─────────────────────
//
// Issue #2106 (epic #2101): the homogeneous-localnet benchmark must show that
// the all-Go and the all-Rust cluster committed the *same* transactions. The
// default mode cannot: its notes carry randomness, its fee follows the
// congestion price and its validity window follows the live round. In
// `--fixed-count N` mode every transaction is a pure function of its sequence
// number (sender, receiver, note, fee, validity window), so two clusters that
// share a genesis are fed byte-identical transactions and equal txid sets can
// be asserted.

/// Fixed tag in every deterministic note (12 bytes, so the note is 24 bytes).
const FIXED_NOTE_TAG: [u8; 12] = *b"algod-bench\0";

/// The note of group member `i` of job `seq`: `seq || i || tag`.
pub fn fixed_note(seq: u64, i: u32) -> Vec<u8> {
    let mut note = Vec::with_capacity(24);
    note.extend_from_slice(&seq.to_be_bytes());
    note.extend_from_slice(&i.to_be_bytes());
    note.extend_from_slice(&FIXED_NOTE_TAG);
    note
}

/// The sender of group member `i` of job `seq`: the ring position
/// `seq * group_size + i` over `n` accounts.
pub fn fixed_sender_index(seq: u64, i: usize, group_size: usize, n: usize) -> usize {
    ((seq as u128 * group_size as u128 + i as u128) % n as u128) as usize
}

/// sha256 (hex) of the sorted, newline-joined txids: equal for equal sets,
/// whatever order the txids were collected in.
pub fn txid_set_digest(txids: &[String]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut sorted: Vec<&str> = txids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    for id in sorted {
        h.update(id.as_bytes());
        h.update(b"\n");
    }
    hex::encode(h.finalize())
}

/// Whether a node's submission error means "this exact transaction is already
/// known" (go-algorand's `ErrAlreadyInLedger` / pool `txn dup`), which a
/// retried deterministic submission treats as accepted.
pub fn is_duplicate_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already in ledger") || m.contains("txn dup") || m.contains("duplicate")
}

/// Build, sign and encode job `seq` of a fixed-count run: the concatenated
/// signed-transaction body to POST and the txid of every member. The result is
/// a pure function of the arguments (ed25519 signatures are deterministic).
fn build_fixed_group(
    accounts: &[LoadAccount],
    seq: u64,
    group_size: usize,
    fee: u64,
    first_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: &str,
) -> anyhow::Result<(Vec<u8>, Vec<String>)> {
    let n = accounts.len();
    let mut txns = Vec::with_capacity(group_size);
    let mut signers = Vec::with_capacity(group_size);
    for i in 0..group_size {
        let a = fixed_sender_index(seq, i, group_size, n);
        let txn = PaymentBuilder::new(accounts[a].address, accounts[(a + 1) % n].address, 0)
            .fee(fee)
            .validity(first_valid, first_valid + 999)
            .genesis_hash(genesis_hash)
            .genesis_id(genesis_id.to_string())
            .note(fixed_note(seq, i as u32))
            .build()
            .map_err(|e| anyhow::anyhow!("build: {e}"))?;
        txns.push(txn);
        signers.push(a);
    }
    if group_size > 1 {
        let gid = compute_group_id(&txns);
        for txn in &mut txns {
            txn.group = gid.0;
        }
    }
    let txids: Vec<String> = txns.iter().map(|t| compute_txn_id(t).to_string()).collect();
    let mut body = Vec::new();
    for (txn, a) in txns.into_iter().zip(signers) {
        let signed = sign_txn(&accounts[a].signing, txn);
        body.extend_from_slice(&canonical_encode_signed_transaction(&signed));
    }
    Ok((body, txids))
}

// ───────────────────────── config + report ─────────────────────────

/// Everything `loadgen run` needs. Mirrors the CLI flags one-for-one.
#[derive(Debug, Clone)]
pub struct LoadgenConfig {
    /// Node REST base URLs to spread submissions across.
    pub endpoints: Vec<String>,
    /// API token presented as `X-Algo-API-Token` to every endpoint.
    pub token: String,
    /// Path to the JSON key file produced by `gen-accounts`.
    pub keys: PathBuf,
    /// Steady-state transactions per second.
    pub target_tps: f64,
    /// Total run length, including the ramp.
    pub duration_secs: f64,
    /// Linear ramp-up length at the start of the run.
    pub ramp_secs: f64,
    /// Transactions per atomic group. 1 means singleton payments.
    pub group_size: usize,
    /// Concurrent submitter tasks per endpoint.
    pub concurrency: usize,
    /// Multiplier applied to the congestion-adjusted fee (see [`effective_fee`]).
    pub fee_multiplier: f64,
    /// Poll confirmation latency for every Nth submission (0 disables).
    pub confirm_sample: u64,
    /// Give up on a confirmation poll after this long.
    pub confirm_timeout_secs: u64,
    /// Where to write the JSON report.
    pub output: Option<PathBuf>,
    /// `--fixed-count`: when non-zero, submit exactly this many groups of
    /// deterministic transactions (see [`build_fixed_group`]), retrying each
    /// until a node accepts it, then verify every txid is confirmed. 0 = the
    /// duration-driven mode.
    pub fixed_count: u64,
    /// First valid round of every fixed-count transaction (last = first + 999).
    pub first_valid: u64,
    /// Fee of every fixed-count transaction, in microAlgos.
    pub fixed_fee: u64,
    /// How long to wait for every fixed-count txid to be confirmed.
    pub settle_secs: u64,
    /// Where to write the sorted txids of a fixed-count run (one per line).
    pub txids_out: Option<PathBuf>,
}

/// Assumed signed-transaction size, in bytes, for fee estimation.
///
/// The generator only ever builds one shape of transaction: a 0-amount payment
/// with a 24-byte note and an ed25519 signature, which encodes to ~263 bytes.
/// Rounding up gives a little headroom without needing to encode the
/// transaction twice (once to measure, once to sign) on the hot path.
const EST_SIGNED_TXN_BYTES: u64 = 300;

/// The fee to put on each generated transaction, in microAlgos.
///
/// `/v2/transactions/params` reports two different things and using the wrong
/// one is the difference between a benchmark that saturates the network and
/// one that stalls: `min_fee` is the *static protocol* minimum (1000), while
/// `fee` is the pool's current **per-byte** congestion price, which rises above
/// the protocol floor exactly when the run gets interesting. Paying `min_fee`
/// therefore works until the pool backs up and then fails every submission with
/// `fee {1000} below threshold N`, capping measured throughput at the point
/// where the network first became congested — the one number a stress test must
/// not be capped by.
///
/// So: charge go-algorand's own rule, `max(fee_per_byte * size, min_fee)`, and
/// scale it by `multiplier` for headroom against the params poll being a few
/// seconds stale.
fn effective_fee(min_fee: u64, fee_per_byte: u64, multiplier: f64) -> u64 {
    let congestion = fee_per_byte.saturating_mul(EST_SIGNED_TXN_BYTES);
    let base = congestion.max(min_fee);
    let scaled = (base as f64) * multiplier.max(1.0);
    // Cap at a value that cannot overflow u64 or drain a funded account in one
    // transaction; 1 Algo per txn is already absurd for a benchmark network.
    (scaled.min(1_000_000.0)) as u64
}

/// Per-endpoint submission tallies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointStats {
    /// Groups (or singletons) POSTed successfully.
    pub accepted_groups: u64,
    /// Groups whose POST returned an error.
    pub failed_groups: u64,
}

/// Confirmation-latency summary, in milliseconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfirmationStats {
    /// Number of sampled transactions that reached a block.
    pub samples: u64,
    /// Sampled transactions that never confirmed within the timeout.
    pub timeouts: u64,
    /// Mean submit → in-block latency.
    pub avg_ms: u64,
    /// Median submit → in-block latency.
    pub p50_ms: u64,
    /// 95th-percentile submit → in-block latency.
    pub p95_ms: u64,
    /// 99th-percentile submit -> in-block latency.
    #[serde(default)]
    pub p99_ms: u64,
    /// Worst observed submit → in-block latency.
    pub max_ms: u64,
}

/// The JSON document written to `--output`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadgenReport {
    /// Always `"loadgen"`; lets a consumer discriminate report kinds.
    pub scenario: String,
    /// RFC3339 UTC completion timestamp.
    pub timestamp: String,
    /// Echo of the requested configuration.
    pub config: serde_json::Value,
    /// Achieved submission numbers.
    pub submission: serde_json::Value,
    /// Submission error message → occurrence count.
    pub errors: HashMap<String, u64>,
    /// Confirmation-latency summary.
    pub confirmation: ConfirmationStats,
    /// Endpoint URL → per-endpoint tallies.
    pub per_endpoint: HashMap<String, EndpointStats>,
    /// Fixed-count runs only: the txid-set evidence (see [`verify_all`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<serde_json::Value>,
}

// ───────────────────────── shared run state ─────────────────────────

struct Shared {
    accounts: Vec<LoadAccount>,
    clients: Vec<AlgodClient>,
    endpoint_names: Vec<String>,
    params: Mutex<SuggestedParams>,
    cfg: LoadgenConfig,

    next_account: AtomicU64,
    dispatched: AtomicU64,
    accepted_groups: AtomicU64,
    failed_groups: AtomicU64,
    backpressure_drops: AtomicU64,
    submit_seq: AtomicU64,
    stop: AtomicBool,

    errors: Mutex<HashMap<String, u64>>,
    per_endpoint: Mutex<HashMap<String, EndpointStats>>,
    latencies: Mutex<Vec<u64>>,
    confirm_timeouts: AtomicU64,
    /// Fixed-count mode: the txid of every accepted transaction.
    accepted_txids: Mutex<Vec<String>>,
}

impl Shared {
    fn record_error(&self, msg: String) {
        // Collapse the long tail: node errors embed txids and round numbers,
        // which would otherwise make every entry unique and the map unbounded.
        let key = msg.chars().take(160).collect::<String>();
        let mut map = self.errors.lock().expect("errors mutex");
        if map.len() < 64 || map.contains_key(&key) {
            *map.entry(key).or_insert(0) += 1;
        } else {
            *map.entry("(other)".to_string()).or_insert(0) += 1;
        }
    }

    fn record_endpoint(&self, name: &str, ok: bool) {
        let mut map = self.per_endpoint.lock().expect("per_endpoint mutex");
        let entry = map.entry(name.to_string()).or_default();
        if ok {
            entry.accepted_groups += 1;
        } else {
            entry.failed_groups += 1;
        }
    }
}

/// Run the load generator to completion and (optionally) write the report.
pub async fn run(cfg: LoadgenConfig) -> anyhow::Result<()> {
    if cfg.endpoints.is_empty() {
        anyhow::bail!("--algod-urls must list at least one endpoint");
    }
    if cfg.group_size == 0 || cfg.group_size > 16 {
        anyhow::bail!("--group-size must be between 1 and 16 (consensus MaxTxGroupSize)");
    }
    if cfg.concurrency == 0 {
        anyhow::bail!("--concurrency must be at least 1");
    }

    let key_json = std::fs::read_to_string(&cfg.keys)
        .map_err(|e| anyhow::anyhow!("reading key file {}: {e}", cfg.keys.display()))?;
    let key_file: KeyFile = serde_json::from_str(&key_json)
        .map_err(|e| anyhow::anyhow!("parsing key file {}: {e}", cfg.keys.display()))?;
    let accounts = key_file.decode()?;

    // A group must be signable by distinct senders only if we want distinct
    // txids; we vary the note instead, so one account per group element is not
    // required. But too few accounts serialises the node's per-account
    // bookkeeping, so warn rather than silently underperform.
    if accounts.len() < cfg.group_size {
        warn!(
            accounts = accounts.len(),
            group_size = cfg.group_size,
            "fewer generator accounts than the group size; group members will reuse senders"
        );
    }

    let clients: Vec<AlgodClient> = cfg
        .endpoints
        .iter()
        .map(|url| AlgodClient::new(url.clone(), cfg.token.clone()))
        .collect();

    // Seed the shared suggested params before any worker starts, so nobody
    // builds a transaction against a zero genesis hash.
    let mut params: Option<SuggestedParams> = None;
    for client in &clients {
        match client.suggested_transaction_params().await {
            Ok(p) => {
                params = Some(p);
                break;
            }
            Err(e) => warn!(error = %e, "endpoint did not serve suggested params"),
        }
    }
    let params = params.ok_or_else(|| {
        anyhow::anyhow!("no endpoint served /v2/transactions/params; is the cluster up?")
    })?;
    info!(
        genesis_id = %params.genesis_id,
        last_round = params.last_round,
        min_fee = params.min_fee,
        endpoints = clients.len(),
        accounts = accounts.len(),
        target_tps = cfg.target_tps,
        duration_secs = cfg.duration_secs,
        group_size = cfg.group_size,
        "loadgen starting"
    );

    let shared = Arc::new(Shared {
        accounts,
        endpoint_names: cfg.endpoints.clone(),
        clients,
        params: Mutex::new(params),
        cfg: cfg.clone(),
        next_account: AtomicU64::new(0),
        dispatched: AtomicU64::new(0),
        accepted_groups: AtomicU64::new(0),
        failed_groups: AtomicU64::new(0),
        backpressure_drops: AtomicU64::new(0),
        submit_seq: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        errors: Mutex::new(HashMap::new()),
        per_endpoint: Mutex::new(HashMap::new()),
        latencies: Mutex::new(Vec::new()),
        confirm_timeouts: AtomicU64::new(0),
        accepted_txids: Mutex::new(Vec::new()),
    });

    // Background params refresher.
    let refresher = {
        let shared = shared.clone();
        tokio::spawn(async move {
            while !shared.stop.load(Ordering::Relaxed) {
                tokio::time::sleep(PARAMS_REFRESH).await;
                for client in &shared.clients {
                    if let Ok(p) = client.suggested_transaction_params().await {
                        *shared.params.lock().expect("params mutex") = p;
                        break;
                    }
                }
            }
        })
    };

    // Bounded job channel. Its depth is the overload signal: a full channel
    // means the submitters cannot keep up with the requested rate, which we
    // report as `backpressure_drops` rather than quietly stretching the run.
    let worker_count = shared.clients.len() * cfg.concurrency;
    let (tx, rx) = tokio::sync::mpsc::channel::<()>(worker_count * 8);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let mut workers = Vec::with_capacity(worker_count);
    for widx in 0..worker_count {
        let shared = shared.clone();
        let rx = rx.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let job = { rx.lock().await.recv().await };
                if job.is_none() {
                    break;
                }
                submit_once(&shared, widx).await;
            }
        }));
    }

    // Scheduler: dispatch the shortfall between the ramp integral and what has
    // actually been handed to the workers.
    let start = Instant::now();
    let total = Duration::from_secs_f64(cfg.duration_secs);
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let per_job = cfg.group_size as f64;
    let mut last_log = Instant::now();

    let fixed = cfg.fixed_count;
    while start.elapsed() < total
        && (fixed == 0 || shared.dispatched.load(Ordering::Relaxed) < fixed)
    {
        ticker.tick().await;
        let elapsed = start.elapsed().as_secs_f64();
        let want_txns = scheduled_by(cfg.target_tps, cfg.ramp_secs, elapsed);
        let mut want_jobs = (want_txns / per_job).floor() as u64;
        if fixed > 0 {
            want_jobs = want_jobs.min(fixed);
        }
        let done_jobs = shared.dispatched.load(Ordering::Relaxed)
            + shared.backpressure_drops.load(Ordering::Relaxed);
        for _ in 0..want_jobs.saturating_sub(done_jobs) {
            if fixed > 0 {
                // Fixed-count mode never drops a job: wait for a free worker.
                if tx.send(()).await.is_err() {
                    break;
                }
                shared.dispatched.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match tx.try_send(()) {
                Ok(()) => {
                    shared.dispatched.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    shared.backpressure_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if last_log.elapsed() >= Duration::from_secs(10) {
            last_log = Instant::now();
            info!(
                elapsed_secs = elapsed as u64,
                target_tps = ramped_tps(cfg.target_tps, cfg.ramp_secs, elapsed) as u64,
                accepted_groups = shared.accepted_groups.load(Ordering::Relaxed),
                failed_groups = shared.failed_groups.load(Ordering::Relaxed),
                backpressure_drops = shared.backpressure_drops.load(Ordering::Relaxed),
                "loadgen progress"
            );
        }
    }

    drop(tx);
    for w in workers {
        let _ = w.await;
    }
    let wall = start.elapsed().as_secs_f64();
    shared.stop.store(true, Ordering::Relaxed);
    refresher.abort();

    // Give in-flight confirmation polls a chance to land before summarising.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let fixed_report = if fixed > 0 {
        Some(verify_all(&shared, start).await)
    } else {
        None
    };
    if let (Some(path), true) = (&cfg.txids_out, fixed > 0) {
        let mut ids = shared.accepted_txids.lock().expect("txids mutex").clone();
        ids.sort_unstable();
        std::fs::write(path, ids.join("\n") + "\n")?;
    }

    let report = build_report(&shared, wall, fixed_report);
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cfg.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, &rendered)?;
        info!(path = %path.display(), "wrote loadgen report");
    }
    println!("{rendered}");
    Ok(())
}

/// Assemble the JSON report from the accumulated counters.
fn build_report(
    shared: &Shared,
    wall_secs: f64,
    fixed: Option<serde_json::Value>,
) -> LoadgenReport {
    let cfg = &shared.cfg;
    let accepted_groups = shared.accepted_groups.load(Ordering::Relaxed);
    let failed_groups = shared.failed_groups.load(Ordering::Relaxed);
    let drops = shared.backpressure_drops.load(Ordering::Relaxed);
    let accepted_txns = accepted_groups * cfg.group_size as u64;

    let mut lat = shared.latencies.lock().expect("latencies mutex").clone();
    lat.sort_unstable();
    let confirmation = ConfirmationStats {
        samples: lat.len() as u64,
        timeouts: shared.confirm_timeouts.load(Ordering::Relaxed),
        avg_ms: if lat.is_empty() {
            0
        } else {
            (lat.iter().sum::<u64>() as f64 / lat.len() as f64).round() as u64
        },
        p50_ms: percentile(&lat, 50.0),
        p95_ms: percentile(&lat, 95.0),
        p99_ms: percentile(&lat, 99.0),
        max_ms: lat.last().copied().unwrap_or(0),
    };

    LoadgenReport {
        scenario: "loadgen".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        config: serde_json::json!({
            "endpoints": cfg.endpoints,
            "target_tps": cfg.target_tps,
            "duration_secs": cfg.duration_secs,
            "ramp_secs": cfg.ramp_secs,
            "group_size": cfg.group_size,
            "concurrency": cfg.concurrency,
            "accounts": shared.accounts.len(),
            "fee_multiplier": cfg.fee_multiplier,
            "confirm_sample": cfg.confirm_sample,
        }),
        submission: serde_json::json!({
            "wall_clock_secs": (wall_secs * 1000.0).round() / 1000.0,
            "accepted_groups": accepted_groups,
            "failed_groups": failed_groups,
            "accepted_txns": accepted_txns,
            "backpressure_drops_groups": drops,
            "achieved_submit_tps":
                if wall_secs > 0.0 { (accepted_txns as f64 / wall_secs * 100.0).round() / 100.0 } else { 0.0 },
            "requested_target_tps": cfg.target_tps,
        }),
        errors: shared.errors.lock().expect("errors mutex").clone(),
        confirmation,
        per_endpoint: shared
            .per_endpoint
            .lock()
            .expect("per_endpoint mutex")
            .clone(),
        fixed,
    }
}

/// How many times a fixed-count submission is retried before the group is
/// counted as failed (50 ms apart, so ~20 s).
const FIXED_MAX_ATTEMPTS: u32 = 400;

/// Fixed-count mode: poll every accepted txid until it is confirmed (or
/// `settle_secs` pass) and summarise the evidence the benchmark gate needs:
/// how many were submitted/confirmed and the digest of both txid sets.
async fn verify_all(shared: &Arc<Shared>, run_start: Instant) -> serde_json::Value {
    let cfg = &shared.cfg;
    let mut ids = shared.accepted_txids.lock().expect("txids mutex").clone();
    ids.sort_unstable();
    let mut confirmed: Vec<Option<u64>> = vec![None; ids.len()];
    let deadline = Instant::now() + Duration::from_secs(cfg.settle_secs);
    let mut last_confirm_secs = 0.0_f64;
    loop {
        let todo: Vec<usize> = (0..ids.len()).filter(|&i| confirmed[i].is_none()).collect();
        if todo.is_empty() {
            break;
        }
        for chunk in todo.chunks(64) {
            let mut set = tokio::task::JoinSet::new();
            for &i in chunk {
                let shared = shared.clone();
                let id = TxId(ids[i].clone());
                set.spawn(async move {
                    let client = &shared.clients[i % shared.clients.len()];
                    let round = match client.get_pending_transaction(&id).await {
                        Ok(info) => info.confirmed_round,
                        Err(_) => None,
                    };
                    (i, round)
                });
            }
            while let Some(done) = set.join_next().await {
                if let Ok((i, Some(round))) = done {
                    confirmed[i] = Some(round);
                    last_confirm_secs = run_start.elapsed().as_secs_f64();
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let confirmed_ids: Vec<String> = ids
        .iter()
        .zip(&confirmed)
        .filter(|(_, r)| r.is_some())
        .map(|(id, _)| id.clone())
        .collect();
    let rounds: Vec<u64> = confirmed.iter().flatten().copied().collect();
    serde_json::json!({
        "expected_groups": cfg.fixed_count,
        "expected_txns": cfg.fixed_count * cfg.group_size as u64,
        "submitted_txns": ids.len(),
        "confirmed_txns": confirmed_ids.len(),
        "unconfirmed_txns": ids.len() - confirmed_ids.len(),
        "submitted_txid_set_sha256": txid_set_digest(&ids),
        "confirmed_txid_set_sha256": txid_set_digest(&confirmed_ids),
        "first_confirmed_round": rounds.iter().min(),
        "last_confirmed_round": rounds.iter().max(),
        "all_confirmed_after_secs": (last_confirm_secs * 1000.0).round() / 1000.0,
        "first_valid": cfg.first_valid,
        "fee": cfg.fixed_fee,
    })
}

/// Fixed-count mode: build job `seq` deterministically and submit it, retrying
/// until a node accepts it (or reports it already known).
async fn submit_fixed(shared: &Arc<Shared>, widx: usize) {
    let cfg = &shared.cfg;
    let endpoint_idx = widx % shared.clients.len();
    let client = &shared.clients[endpoint_idx];
    let endpoint = &shared.endpoint_names[endpoint_idx];
    let seq = shared.submit_seq.fetch_add(1, Ordering::Relaxed);
    let (genesis_hash, genesis_id) = {
        let p = shared.params.lock().expect("params mutex");
        (p.genesis_hash.0, p.genesis_id.clone())
    };
    let (body, txids) = match build_fixed_group(
        &shared.accounts,
        seq,
        cfg.group_size,
        cfg.fixed_fee,
        cfg.first_valid,
        genesis_hash,
        &genesis_id,
    ) {
        Ok(v) => v,
        Err(e) => {
            shared.failed_groups.fetch_add(1, Ordering::Relaxed);
            shared.record_error(e.to_string());
            return;
        }
    };
    let submitted_at = Instant::now();
    let mut attempts = 0u32;
    loop {
        match client.send_raw_transaction(&body).await {
            Ok(txid) => {
                shared.accepted_groups.fetch_add(1, Ordering::Relaxed);
                shared.record_endpoint(endpoint, true);
                if cfg.confirm_sample > 0 && seq.is_multiple_of(cfg.confirm_sample) {
                    spawn_confirm_probe(shared.clone(), endpoint_idx, txid, submitted_at);
                }
                break;
            }
            Err(e) => {
                let msg = e.to_string();
                if is_duplicate_error(&msg) {
                    shared.accepted_groups.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                shared.record_endpoint(endpoint, false);
                shared.record_error(msg);
                attempts += 1;
                if attempts >= FIXED_MAX_ATTEMPTS {
                    shared.failed_groups.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    shared
        .accepted_txids
        .lock()
        .expect("txids mutex")
        .extend(txids);
}

/// Build, sign, and POST one transaction group from worker `widx`.
async fn submit_once(shared: &Arc<Shared>, widx: usize) {
    if shared.cfg.fixed_count > 0 {
        return submit_fixed(shared, widx).await;
    }
    let cfg = &shared.cfg;
    let endpoint_idx = widx % shared.clients.len();
    let client = &shared.clients[endpoint_idx];
    let endpoint = &shared.endpoint_names[endpoint_idx];

    let params = shared.params.lock().expect("params mutex").clone();
    let fee = effective_fee(params.min_fee, params.fee, cfg.fee_multiplier);
    let seq = shared.submit_seq.fetch_add(1, Ordering::Relaxed);

    let mut txns = Vec::with_capacity(cfg.group_size);
    let mut signers = Vec::with_capacity(cfg.group_size);
    for i in 0..cfg.group_size {
        let a =
            shared.next_account.fetch_add(1, Ordering::Relaxed) as usize % shared.accounts.len();
        let sender = &shared.accounts[a];
        // Send to the next account in the ring so the payment actually moves
        // value between distinct accounts (a self-payment is legal but exercises
        // one fewer accountbase write on the apply path).
        let receiver = &shared.accounts[(a + 1) % shared.accounts.len()];
        // 24-byte note: worker + sequence + group index + randomness. The
        // randomness is what guarantees uniqueness across restarts of the
        // generator against a still-live network.
        let mut note = Vec::with_capacity(24);
        note.extend_from_slice(&(widx as u64).to_be_bytes());
        note.extend_from_slice(&seq.to_be_bytes());
        note.extend_from_slice(&(i as u32).to_be_bytes());
        note.extend_from_slice(&rand::random::<u32>().to_be_bytes());
        let built = PaymentBuilder::new(sender.address, receiver.address, 0)
            .fee(fee)
            .validity(params.last_round, params.last_round + 1000)
            .genesis_hash(params.genesis_hash.0)
            .genesis_id(params.genesis_id.clone())
            .note(note)
            .build();
        match built {
            Ok(txn) => {
                txns.push(txn);
                signers.push(a);
            }
            Err(e) => {
                shared.failed_groups.fetch_add(1, Ordering::Relaxed);
                shared.record_error(format!("build: {e}"));
                shared.record_endpoint(endpoint, false);
                return;
            }
        }
    }

    if cfg.group_size > 1 {
        let gid = compute_group_id(&txns);
        for txn in &mut txns {
            txn.group = gid.0;
        }
    }

    let mut body = Vec::new();
    for (txn, &a) in txns.into_iter().zip(signers.iter()) {
        let signed = sign_txn(&shared.accounts[a].signing, txn);
        body.extend_from_slice(&canonical_encode_signed_transaction(&signed));
    }

    let submitted_at = Instant::now();
    match client.send_raw_transaction(&body).await {
        Ok(txid) => {
            shared.accepted_groups.fetch_add(1, Ordering::Relaxed);
            shared.record_endpoint(endpoint, true);
            if cfg.confirm_sample > 0 && seq.is_multiple_of(cfg.confirm_sample) {
                spawn_confirm_probe(shared.clone(), endpoint_idx, txid, submitted_at);
            }
        }
        Err(e) => {
            shared.failed_groups.fetch_add(1, Ordering::Relaxed);
            shared.record_endpoint(endpoint, false);
            shared.record_error(e.to_string());
            debug!(error = %e, endpoint, "submission failed");
        }
    }
}

/// Poll `/v2/transactions/pending/{txid}` until the transaction lands in a
/// block, recording submit → in-block wall time.
fn spawn_confirm_probe(
    shared: Arc<Shared>,
    endpoint_idx: usize,
    txid: TxId,
    submitted_at: Instant,
) {
    tokio::spawn(async move {
        let deadline = Duration::from_secs(shared.cfg.confirm_timeout_secs);
        let client = &shared.clients[endpoint_idx];
        loop {
            if submitted_at.elapsed() >= deadline {
                shared.confirm_timeouts.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if let Ok(info) = client.get_pending_transaction(&txid).await {
                if info.confirmed_round.is_some() {
                    let ms = submitted_at.elapsed().as_millis() as u64;
                    shared.latencies.lock().expect("latencies mutex").push(ms);
                    return;
                }
                if !info.pool_error.is_empty() {
                    shared.record_error(format!("pool: {}", info.pool_error));
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the node-side signature check over a single (ungrouped)
    /// transaction, so the tests assert against the exact verifier a real
    /// node applies rather than re-implementing ed25519 verification.
    fn verify_single(stx: &SignedTransaction) -> Result<(), algo_error::AlgoError> {
        let consensus = algo_types::consensus_params_for_version(
            algo_types::consensus::CONSENSUS_CURRENT_VERSION,
        )
        .expect("current consensus params");
        let mut budget = algo_avm::group::GroupBudget::new(0);
        let group = [stx.clone()];
        algo_validate::signature::verify_transaction_signature(
            stx,
            &group,
            0,
            &mut budget,
            &consensus,
        )
    }

    #[test]
    fn ramped_tps_is_zero_at_start_and_flat_after_ramp() {
        assert_eq!(ramped_tps(1000.0, 30.0, 0.0), 0.0);
        assert_eq!(ramped_tps(1000.0, 30.0, 15.0), 500.0);
        assert_eq!(ramped_tps(1000.0, 30.0, 30.0), 1000.0);
        assert_eq!(ramped_tps(1000.0, 30.0, 120.0), 1000.0);
    }

    #[test]
    fn ramped_tps_without_ramp_is_immediately_at_target() {
        assert_eq!(ramped_tps(500.0, 0.0, 0.0), 500.0);
        assert_eq!(ramped_tps(0.0, 30.0, 10.0), 0.0);
    }

    #[test]
    fn scheduled_by_matches_the_ramp_integral() {
        // Triangle area at the end of a 30s ramp to 1000 TPS = 15_000 txns.
        assert!((scheduled_by(1000.0, 30.0, 30.0) - 15_000.0).abs() < 1e-6);
        // Halfway up the ramp: 1000 * 15² / 60 = 3750.
        assert!((scheduled_by(1000.0, 30.0, 15.0) - 3_750.0).abs() < 1e-6);
        // Triangle + 10s of flat.
        assert!((scheduled_by(1000.0, 30.0, 40.0) - 25_000.0).abs() < 1e-6);
        // No ramp: pure rate * time.
        assert!((scheduled_by(100.0, 0.0, 7.0) - 700.0).abs() < 1e-6);
        assert_eq!(scheduled_by(100.0, 10.0, 0.0), 0.0);
    }

    #[test]
    fn scheduled_by_is_monotonic() {
        let mut prev = 0.0;
        for i in 0..200 {
            let v = scheduled_by(250.0, 30.0, i as f64 * 0.5);
            assert!(v >= prev, "not monotonic at t={i}");
            prev = v;
        }
    }

    #[test]
    fn percentile_uses_nearest_rank() {
        let data = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile(&data, 50.0), 50);
        assert_eq!(percentile(&data, 95.0), 100);
        assert_eq!(percentile(&data, 100.0), 100);
        assert_eq!(percentile(&data, 10.0), 10);
        assert_eq!(percentile(&[], 50.0), 0);
        assert_eq!(percentile(&[42], 95.0), 42);
    }

    #[test]
    fn gen_accounts_roundtrips_through_decode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys.json");
        gen_accounts(4, &path).expect("gen");
        let text = std::fs::read_to_string(&path).expect("read");
        let file: KeyFile = serde_json::from_str(&text).expect("parse");
        assert_eq!(file.accounts.len(), 4);
        let decoded = file.decode().expect("decode");
        assert_eq!(decoded.len(), 4);
        // Addresses are distinct and self-consistent.
        let mut seen = std::collections::HashSet::new();
        for acct in &decoded {
            assert!(seen.insert(acct.address));
            assert_eq!(
                Address(acct.signing.verifying_key().to_bytes()),
                acct.address
            );
        }
    }

    /// Direct port of go-algorand's `shared/pingpong.TestDeterministicAccounts`:
    /// deterministic seeds are derived purely from the sequential index
    /// (`binary.LittleEndian.PutUint64(seed[:], i)`), so re-deriving the
    /// same index always reproduces the same keypair, and generating
    /// `count` deterministic accounts must match a keypair independently
    /// derived from that same index -- exactly the property go's test
    /// checks (`expectedPubKeys` built via `makeKeyFromSeed`, then checked
    /// against `deterministicAccounts`'s output).
    #[test]
    fn deterministic_seed_matches_go_makekeyfromseed_construction() {
        // Build the "expected" set the same way go's test does: index -> keypair.
        let expected: std::collections::HashMap<[u8; 32], u64> = (0..100u64)
            .map(|i| {
                let signing = SigningKey::from_bytes(&deterministic_seed(i));
                (signing.verifying_key().to_bytes(), i)
            })
            .collect();
        assert_eq!(expected.len(), 100, "100 distinct deterministic keys");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("det.json");
        gen_accounts_deterministic(20, &path).expect("gen deterministic");
        let text = std::fs::read_to_string(&path).expect("read");
        let file: KeyFile = serde_json::from_str(&text).expect("parse");
        assert_eq!(file.accounts.len(), 20);

        let decoded = file.decode().expect("decode");
        assert_eq!(decoded.len(), 20);
        for acct in &decoded {
            let pubkey = acct.signing.verifying_key().to_bytes();
            assert!(
                expected.contains_key(&pubkey),
                "generated account {} not found in the independently-derived set",
                acct.address
            );
        }

        // Re-generating deterministically for the same count must
        // reproduce byte-identical seeds every time.
        let path2 = dir.path().join("det2.json");
        gen_accounts_deterministic(20, &path2).expect("gen deterministic again");
        let text2 = std::fs::read_to_string(&path2).expect("read");
        assert_eq!(text, text2, "deterministic generation must be reproducible");
    }

    #[test]
    fn deterministic_seed_is_little_endian_index_zero_padded() {
        // Matches go's `binary.LittleEndian.PutUint64(seed[:], i)` exactly.
        let seed = deterministic_seed(0x0102_0304_0506_0708);
        assert_eq!(
            &seed[..8],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&seed[8..], &[0u8; 24]);
    }

    #[test]
    fn gen_accounts_rejects_zero_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(gen_accounts(0, &dir.path().join("k.json")).is_err());
    }

    #[test]
    fn decode_rejects_address_seed_mismatch() {
        let file = KeyFile {
            accounts: vec![AccountKey {
                // Valid checksummed address, but not this seed's public key.
                address: Address::ZERO.to_algorand_string(),
                seed: hex::encode([7u8; 32]),
            }],
        };
        let err = file.decode().expect_err("mismatch must be rejected");
        assert!(err.to_string().contains("does not match its seed"));
    }

    #[test]
    fn decode_rejects_short_seed() {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let file = KeyFile {
            accounts: vec![AccountKey {
                address: Address(signing.verifying_key().to_bytes()).to_algorand_string(),
                seed: hex::encode([3u8; 16]),
            }],
        };
        let err = file.decode().expect_err("short seed must be rejected");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn decode_rejects_empty_file() {
        assert!(KeyFile::default().decode().is_err());
    }

    #[test]
    fn sign_txn_produces_a_signature_the_validator_accepts() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let sender = Address(signing.verifying_key().to_bytes());
        let txn = PaymentBuilder::new(sender, Address::ZERO, 1)
            .fee(1000)
            .validity(1, 1001)
            .genesis_hash([1u8; 32])
            .note(vec![1, 2, 3])
            .build()
            .expect("build");
        let signed = sign_txn(&signing, txn);
        assert_ne!(signed.sig, [0u8; 64]);
        verify_single(&signed).expect("self-signed txn must verify");
    }

    #[test]
    fn sign_txn_binds_to_the_transaction_body() {
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let sender = Address(signing.verifying_key().to_bytes());
        let build = |note: Vec<u8>| {
            PaymentBuilder::new(sender, Address::ZERO, 1)
                .fee(1000)
                .validity(1, 1001)
                .genesis_hash([1u8; 32])
                .note(note)
                .build()
                .expect("build")
        };
        let a = sign_txn(&signing, build(vec![1]));
        let b = sign_txn(&signing, build(vec![2]));
        assert_ne!(a.sig, b.sig);
        // Splicing A's signature onto B's body must not verify.
        let mut forged = b.clone();
        forged.sig = a.sig;
        assert!(verify_single(&forged).is_err());
    }

    #[test]
    fn effective_fee_uses_protocol_minimum_on_an_idle_network() {
        // Idle pool: go-algorand suggests 1 µAlgo/byte, which is far below the
        // protocol floor for a ~300-byte payment, so the floor must win.
        assert_eq!(effective_fee(1000, 1, 1.0), 1000);
    }

    #[test]
    fn effective_fee_tracks_the_congestion_price() {
        // The exact case that broke the 1000 TPS run: the pool raised its floor
        // to 4 µAlgo/byte and every 1000 µAlgo submission was rejected with
        // "fee {1000} below threshold 1052".
        assert_eq!(effective_fee(1000, 4, 1.0), 1200);
        assert!(effective_fee(1000, 4, 1.0) > 1052);
    }

    #[test]
    fn effective_fee_multiplier_only_ever_adds_headroom() {
        // A multiplier below 1.0 would underpay and reintroduce the very
        // rejection this function exists to avoid, so it is clamped.
        assert_eq!(effective_fee(1000, 4, 0.1), 1200);
        assert_eq!(effective_fee(1000, 4, 2.0), 2400);
    }

    #[test]
    fn effective_fee_is_capped_and_overflow_safe() {
        // A malfunctioning or hostile endpoint reporting an absurd per-byte
        // price must not overflow or empty a generator account in one txn.
        assert_eq!(effective_fee(1000, u64::MAX, 1_000.0), 1_000_000);
    }

    // ── fixed-count (deterministic) mode, issue #2106 ──

    fn fixed_accounts(n: u64) -> Vec<LoadAccount> {
        (0..n)
            .map(|i| {
                let signing = SigningKey::from_bytes(&deterministic_seed(i));
                LoadAccount {
                    address: Address(signing.verifying_key().to_bytes()),
                    signing,
                }
            })
            .collect()
    }

    #[test]
    fn fixed_note_is_a_pure_function_of_seq_and_index() {
        assert_eq!(fixed_note(7, 2), fixed_note(7, 2));
        assert_ne!(fixed_note(7, 2), fixed_note(8, 2));
        assert_ne!(fixed_note(7, 2), fixed_note(7, 3));
        assert_eq!(fixed_note(7, 2).len(), 24);
        assert_eq!(&fixed_note(0x0102, 3)[..8], &0x0102u64.to_be_bytes());
    }

    #[test]
    fn fixed_sender_index_walks_the_ring_across_groups() {
        // group size 4 over 16 accounts: group 0 uses 0..4, group 1 uses 4..8.
        assert_eq!(fixed_sender_index(0, 0, 4, 16), 0);
        assert_eq!(fixed_sender_index(0, 3, 4, 16), 3);
        assert_eq!(fixed_sender_index(1, 0, 4, 16), 4);
        assert_eq!(fixed_sender_index(4, 0, 4, 16), 0);
    }

    #[test]
    fn txid_set_digest_ignores_order_and_detects_any_difference() {
        let a = vec!["B".to_string(), "A".to_string(), "C".to_string()];
        let b = vec!["C".to_string(), "B".to_string(), "A".to_string()];
        assert_eq!(txid_set_digest(&a), txid_set_digest(&b));
        let c = vec!["A".to_string(), "B".to_string(), "D".to_string()];
        assert_ne!(txid_set_digest(&a), txid_set_digest(&c));
        assert_ne!(txid_set_digest(&a), txid_set_digest(&a[..2]));
        assert_eq!(txid_set_digest(&a).len(), 64);
    }

    #[test]
    fn fixed_group_is_byte_identical_across_builds() {
        let accounts = fixed_accounts(8);
        let build =
            || build_fixed_group(&accounts, 5, 3, 10_000, 1, [7u8; 32], "bench-v1").expect("build");
        let (body_a, ids_a) = build();
        let (body_b, ids_b) = build();
        assert_eq!(body_a, body_b, "same inputs must give the same bytes");
        assert_eq!(ids_a, ids_b);
        assert_eq!(ids_a.len(), 3);
        let (other, _) =
            build_fixed_group(&accounts, 6, 3, 10_000, 1, [7u8; 32], "bench-v1").expect("build");
        assert_ne!(body_a, other);
    }

    #[test]
    fn fixed_group_txids_are_the_real_txids_of_the_signed_transactions() {
        let accounts = fixed_accounts(4);
        let (body, ids) =
            build_fixed_group(&accounts, 1, 1, 2_000, 1, [9u8; 32], "bench-v1").expect("build");
        let stx: SignedTransaction = algo_codec::decode_signed_txn_stream(&body)
            .expect("the body is one canonical signed transaction")
            .remove(0);
        assert_eq!(ids, vec![compute_txn_id(&stx.txn).to_string()]);
        assert_eq!(stx.txn.fee, 2_000);
        assert_eq!(stx.txn.first_valid, algo_types::Round(1));
        assert_eq!(stx.txn.last_valid, algo_types::Round(1000));
    }

    #[test]
    fn duplicate_submissions_are_recognised() {
        assert!(is_duplicate_error("transaction already in ledger: ABC"));
        assert!(is_duplicate_error("TransactionPool.Remember: txn dup: ABC"));
        assert!(!is_duplicate_error("fee {1000} below threshold 1052"));
    }

    #[test]
    fn percentile_p99_is_reported() {
        let data: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&data, 99.0), 99);
    }
}
