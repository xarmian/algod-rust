//! `algo-cert-crossverify` binary (PLAN-32 / TASK-88).
//!
//! Cross-verifies that a certificate produced by a go-algorand node
//! authenticates cleanly under algod-rust's verifier. For each round in
//! a range (or a sampled subset), we:
//!
//!   1. Fetch `(block, cert)` from a go-algorand REST endpoint.
//!   2. Decode the cert into a Rust `Certificate` via the same codec
//!      path algod-rust's gossip layer uses.
//!   3. Open a caught-up SQLite ledger (normally produced by the Rust
//!      relay in the mixed cluster) read-only.
//!   4. Call `Certificate::authenticate(block_round, block_digest,
//!      &AgreementLedgerBridge)`.
//!   5. Aggregate per-round pass/fail into a summary (and optional
//!      JSONL trace).
//!
//! The binary exits non-zero on any authentication failure.
//!
//! Rust → Go verification (the inverse direction) requires the Rust
//! node to actively produce certs, which is gated on participation-key
//! interop with go-algorand (PLAN-35). Until that ships, this tool only
//! exercises Go → Rust.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::LedgerReader;
use algo_cert_crossverify::{pair_from_response, VerifiablePair};
use algo_ledger::{agreement_bridge::AgreementLedgerBridge, sqlite::SqliteLedger};
use algo_rest_client::{AlgodClient, BlockSource, ClientConfig};
use algo_types::Round;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "algo-cert-crossverify",
    about = "PLAN-32 / TASK-88 Go → Rust certificate cross-verification"
)]
struct Cli {
    /// Base URL of the go-algorand REST endpoint to fetch (block, cert)
    /// pairs from (e.g. http://127.0.0.1:4001).
    #[arg(long)]
    node: String,

    /// Path to the API token file for the source node.
    #[arg(long, conflicts_with = "token")]
    token_file: Option<PathBuf>,

    /// API token value (alternative to --token-file).
    #[arg(long)]
    token: Option<String>,

    /// Path to a read-only SQLite ledger that has already caught up at
    /// least to --to-round. In the TASK-86 harness this comes from
    /// copying the Rust relay's ledger.sqlite out of the container.
    #[arg(long)]
    ledger_sqlite: PathBuf,

    /// First round to verify (inclusive).
    #[arg(long)]
    from_round: u64,

    /// Last round to verify (inclusive).
    #[arg(long)]
    to_round: u64,

    /// Only verify every Nth round in the range (default: 1 = every
    /// round). Useful for "sample 10 rounds across a 200-round soak".
    #[arg(long, default_value_t = 1)]
    stride: u64,

    /// Emit per-round records as JSONL to this path (in addition to
    /// the stdout summary).
    #[arg(long)]
    jsonl_out: Option<PathBuf>,

    /// Per-request HTTP timeout in seconds (default: 10).
    #[arg(long, default_value_t = 10)]
    timeout_s: u64,

    /// Tracing log level (default: info).
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsonlRecord {
    Round {
        round: u64,
        outcome: &'static str,
        cert_round: u64,
        cert_period: u64,
        block_digest_hex: String,
        votes: usize,
        error: Option<String>,
    },
    Summary {
        from_round: u64,
        to_round: u64,
        stride: u64,
        rounds_verified: usize,
        rounds_ok: usize,
        rounds_failed: usize,
        rounds_skipped_fetch: usize,
        node: String,
        ledger_sqlite: String,
    },
}

fn init_tracing(level: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

fn load_token(cli: &Cli) -> Result<String> {
    if let Some(path) = &cli.token_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading token file {}", path.display()))?;
        Ok(raw.trim().to_string())
    } else if let Some(tok) = &cli.token {
        Ok(tok.clone())
    } else {
        bail!("either --token-file or --token is required")
    }
}

fn open_bridge(path: &std::path::Path) -> Result<AgreementLedgerBridge> {
    if !path.exists() {
        bail!("ledger sqlite not found at {}", path.display());
    }
    let ledger = SqliteLedger::open(path)
        .with_context(|| format!("opening SqliteLedger at {}", path.display()))?;
    Ok(AgreementLedgerBridge::new(Arc::new(Mutex::new(ledger))))
}

/// Sanity check: the mixed-cluster Rust node today runs in "relay" mode,
/// which stores raw block blobs with empty `proto` + `hdrdata` and does
/// NOT populate the participation tracker. `Certificate::authenticate`
/// can't run under that ledger — it fails on the first
/// `consensus_params(round)` call with an empty protocol version.
///
/// Fail fast with a clear pointer to the follow-up task rather than
/// letting the user watch every round fail with a cryptic "unknown
/// consensus version: """ error.
fn assert_full_sync_ledger(bridge: &AgreementLedgerBridge, probe_round: Round) -> Result<()> {
    match bridge.consensus_version(probe_round) {
        Ok(version) if !version.is_empty() => Ok(()),
        Ok(empty) => Err(anyhow!(
            "ledger reports an empty consensus version at round {} (got {:?}).\n\
             This looks like a relay-mode sqlite — imported blocks don't populate \
             proto/hdrdata or the participation tracker. A full-sync algod-rust \
             ledger is required. Tracked under TASK-95 (PLAN-32 follow-up).",
            probe_round.0,
            empty
        )),
        Err(e) => Err(anyhow!(
            "ledger probe for round {} failed: {}. Is the ledger caught up past \
             the verify range? See TASK-95.",
            probe_round.0,
            e
        )),
    }
}

async fn run(cli: Cli) -> Result<i32> {
    init_tracing(&cli.log_level);

    if cli.from_round > cli.to_round {
        bail!(
            "--from-round ({}) must be <= --to-round ({})",
            cli.from_round,
            cli.to_round
        );
    }
    if cli.stride == 0 {
        bail!("--stride must be >= 1");
    }

    let token = load_token(&cli)?;
    let client_config = ClientConfig {
        timeout: Duration::from_secs(cli.timeout_s),
        ..ClientConfig::default()
    };
    let client = AlgodClient::with_config(cli.node.clone(), token, client_config);

    // Open the ledger once and share the bridge across the loop.
    let bridge = open_bridge(&cli.ledger_sqlite)?;

    // Fail fast if the ledger doesn't already cover the requested range.
    let next_round = bridge.next_round();
    if next_round.0 <= cli.to_round {
        bail!(
            "ledger at {} is only caught up through round {} (next={}); \
             --to-round is {} — re-run after the Rust relay has synced.",
            cli.ledger_sqlite.display(),
            next_round.0.saturating_sub(1),
            next_round.0,
            cli.to_round
        );
    }
    info!(
        "ledger next_round={}; covering verify range {}..={} stride={}",
        next_round.0, cli.from_round, cli.to_round, cli.stride
    );

    // Confirm the ledger actually has stored protocol + header data for
    // this range — the relay-mode store_block shortcut leaves both empty,
    // which would otherwise manifest as "unknown consensus version:" on
    // every round. Fail fast with a pointer to the follow-up task.
    assert_full_sync_ledger(&bridge, Round(cli.from_round))?;

    // Build the set of rounds to verify up-front so the summary reports
    // exactly what was attempted.
    let mut rounds: BTreeSet<u64> = BTreeSet::new();
    let mut r = cli.from_round;
    while r <= cli.to_round {
        rounds.insert(r);
        r = match r.checked_add(cli.stride) {
            Some(next) => next,
            None => break,
        };
    }
    // Always include the final round so range-spanning verifications don't
    // drop the end.
    rounds.insert(cli.to_round);

    let mut jsonl_writer = match &cli.jsonl_out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
            }
            Some(std::io::BufWriter::new(
                fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
            ))
        }
        None => None,
    };

    let mut rounds_ok = 0usize;
    let mut rounds_failed = 0usize;
    let mut rounds_skipped_fetch = 0usize;
    let total_rounds = rounds.len();

    for round in rounds {
        let algo_round = Round(round);
        let resp = match client.get_block(algo_round).await {
            Ok(r) => r,
            Err(e) => {
                warn!(round = round, error = %e, "block fetch failed — skipping");
                rounds_skipped_fetch += 1;
                if let Some(w) = jsonl_writer.as_mut() {
                    write_jsonl(
                        w,
                        &JsonlRecord::Round {
                            round,
                            outcome: "skipped_fetch",
                            cert_round: 0,
                            cert_period: 0,
                            block_digest_hex: String::new(),
                            votes: 0,
                            error: Some(e.to_string()),
                        },
                    )?;
                }
                continue;
            }
        };

        let pair = match pair_from_response(resp) {
            Ok(p) => p,
            Err(e) => {
                warn!(round = round, error = %e, "decode pair failed");
                rounds_failed += 1;
                if let Some(w) = jsonl_writer.as_mut() {
                    write_jsonl(
                        w,
                        &JsonlRecord::Round {
                            round,
                            outcome: "decode_failed",
                            cert_round: 0,
                            cert_period: 0,
                            block_digest_hex: String::new(),
                            votes: 0,
                            error: Some(e.to_string()),
                        },
                    )?;
                }
                continue;
            }
        };
        let VerifiablePair {
            block,
            block_digest,
            certificate,
        } = pair;

        debug!(
            round = round,
            cert_round = certificate.round.0,
            cert_period = certificate.period.0,
            votes = certificate.votes.len(),
            "verifying cert"
        );

        let outcome_err = certificate
            .authenticate(block.round, block_digest, &bridge)
            .err();
        let outcome = if outcome_err.is_none() {
            rounds_ok += 1;
            "ok"
        } else {
            rounds_failed += 1;
            "authenticate_failed"
        };

        if let Some(w) = jsonl_writer.as_mut() {
            write_jsonl(
                w,
                &JsonlRecord::Round {
                    round,
                    outcome,
                    cert_round: certificate.round.0,
                    cert_period: certificate.period.0,
                    block_digest_hex: hex::encode(block_digest.as_bytes()),
                    votes: certificate.votes.len(),
                    error: outcome_err.as_ref().map(|e| e.to_string()),
                },
            )?;
        }

        if let Some(err) = outcome_err {
            // Print the failing round inline so the operator sees it
            // without having to open the JSONL.
            println!(
                "FAIL round={round}: {err} (cert_round={} votes={})",
                certificate.round.0,
                certificate.votes.len()
            );
        }
    }

    if let Some(mut w) = jsonl_writer.take() {
        write_jsonl(
            &mut w,
            &JsonlRecord::Summary {
                from_round: cli.from_round,
                to_round: cli.to_round,
                stride: cli.stride,
                rounds_verified: total_rounds,
                rounds_ok,
                rounds_failed,
                rounds_skipped_fetch,
                node: cli.node.clone(),
                ledger_sqlite: cli.ledger_sqlite.display().to_string(),
            },
        )?;
    }

    println!(
        "cert-crossverify: node={} ledger={} rounds={} ok={} failed={} fetch_skipped={}",
        cli.node,
        cli.ledger_sqlite.display(),
        total_rounds,
        rounds_ok,
        rounds_failed,
        rounds_skipped_fetch,
    );

    if rounds_failed > 0 {
        Ok(2)
    } else if rounds_ok == 0 {
        // No successful verifications — something went wrong upstream.
        Err(anyhow!("no rounds verified successfully (all skipped?)"))
    } else {
        Ok(0)
    }
}

fn write_jsonl<W: std::io::Write>(w: &mut W, rec: &JsonlRecord) -> Result<()> {
    serde_json::to_writer(&mut *w, rec)?;
    w.write_all(b"\n")?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    let rc = rt.block_on(run(cli))?;
    std::process::exit(rc);
}
