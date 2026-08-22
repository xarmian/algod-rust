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
//! ## Rust → Go (issue #470 §2)
//!
//! Now that the Rust node participates for real (#469), two extra
//! assertions are available:
//!
//!   * `--rust-account ADDR` records, per round, whether that account's
//!     vote is present in the committed certificate, and
//!     `--min-rust-vote-rounds N` fails the run when fewer than N of the
//!     sampled rounds carry one. A Rust vote inside a certificate the
//!     **Go** nodes assembled and committed is direct evidence that Go
//!     accepted and counted it.
//!   * `--export-go-input PATH` writes a JSON bundle (raw `(block,
//!     cert)` msgpack + the ledger facts `agreement.LedgerReader` needs)
//!     for `tools/cert-authenticate`, which replays each certificate
//!     through go-algorand's own `agreement.Certificate.Authenticate`.
//!     Running both gives the "authenticates under BOTH implementations"
//!     property the issue asks for.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_agreement::LedgerReader;
use algo_cert_crossverify::{
    build_go_verify_round, cert_contains_sender, pair_from_response, GoVerifyInput, GoVerifyRound,
    VerifiablePair,
};
use algo_ledger::{agreement_bridge::AgreementLedgerBridge, sqlite::SqliteLedger};
use algo_rest_client::{AlgodClient, BlockSource, ClientConfig};
use algo_types::{Address, Round};
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

    /// (#470 §2) Address of the Rust participant. When set, each round
    /// records whether that account's vote is present in the cert.
    #[arg(long)]
    rust_account: Option<String>,

    /// (#470 §2) Fail unless at least this many of the sampled rounds
    /// carry a vote from --rust-account. 0 disables the gate; 1 is the
    /// "the Rust node is participating at all" assertion.
    #[arg(long, default_value_t = 0, requires = "rust_account")]
    min_rust_vote_rounds: usize,

    /// (#470 §2) Write a JSON bundle for `tools/cert-authenticate` (the
    /// go-algorand-side authenticator) to this path.
    #[arg(long)]
    export_go_input: Option<PathBuf>,
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
        /// (#470 §2) `Some(true)`/`Some(false)` when --rust-account is
        /// configured; `None` when it isn't.
        rust_vote_present: Option<bool>,
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
        /// (#470 §2) Rust participant address, when configured.
        rust_account: Option<String>,
        /// (#470 §2) How many sampled rounds carried a Rust vote.
        rust_vote_rounds: usize,
        /// (#470 §2) The rounds themselves (bounded to the first 64 for
        /// readability; the per-round records carry the full picture).
        rust_vote_round_sample: Vec<u64>,
        /// (#470 §2) The gate that was applied, if any.
        min_rust_vote_rounds: usize,
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
    // `path` is a ledger prefix (or a legacy `.sqlite`-suffixed value);
    // since TASK-100 the on-disk DB is a pair (`<prefix>.tracker.sqlite`
    // + `<prefix>.block.sqlite`), so checking `path.exists()` would
    // reject every valid ledger. Use the split-aware helper.
    if !algo_ledger::ledger_exists(path) {
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
/// Probe **three** fields the verifier actually depends on so a ledger
/// that has partial state (e.g. proto populated but hdrdata empty, or
/// hdrdata populated but `onlineaccounts` never tracked) still trips
/// preflight rather than silently failing round-by-round later:
///
///   - `consensus_version(r)` — non-empty; fails on relay-mode proto.
///   - `seed(r)` — needs `hdrdata` to decode.
///   - `lookup_digest(r)` — also needs `hdrdata`, different codepath.
///
/// We deliberately do NOT probe `circulation` / `lookup_agreement` here
/// because those have fall-back paths that return plausible-looking
/// values off the genesis totals even when the onlineaccounts /
/// onlineroundparamstail tables are empty. A ledger that passes all
/// three of the above but has no participation tracker would still
/// fail verification at the bundle step — and that's the exact error
/// TASK-95 is tracking.
fn assert_full_sync_ledger(bridge: &AgreementLedgerBridge, probe_round: Round) -> Result<()> {
    let task95_hint = "This looks like a relay-mode sqlite — imported blocks don't \
         populate proto/hdrdata or the participation tracker. A \
         full-sync algod-rust ledger is required. Tracked under \
         TASK-95 (PLAN-32 follow-up).";

    match bridge.consensus_version(probe_round) {
        Ok(version) if !version.is_empty() => {}
        Ok(empty) => {
            return Err(anyhow!(
                "ledger reports an empty consensus version at round {} (got {:?}).\n{}",
                probe_round.0,
                empty,
                task95_hint,
            ));
        }
        Err(e) => {
            return Err(anyhow!(
                "ledger probe for round {} consensus_version failed: {}. Is the \
                 ledger caught up past the verify range? See TASK-95.",
                probe_round.0,
                e
            ));
        }
    }
    if let Err(e) = bridge.seed(probe_round) {
        return Err(anyhow!(
            "ledger probe for round {} seed() failed: {}. {}",
            probe_round.0,
            e,
            task95_hint
        ));
    }
    if let Err(e) = bridge.lookup_digest(probe_round) {
        return Err(anyhow!(
            "ledger probe for round {} lookup_digest() failed: {}. {}",
            probe_round.0,
            e,
            task95_hint
        ));
    }
    Ok(())
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

    let rust_account = match &cli.rust_account {
        Some(s) => Some(
            Address::from_str(s.trim())
                .map_err(|e| anyhow!("--rust-account {s:?} is not a valid address: {e:?}"))?,
        ),
        None => None,
    };

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
    let mut rust_vote_rounds: Vec<u64> = Vec::new();
    let mut go_verify_rounds: Vec<GoVerifyRound> = Vec::new();
    let total_rounds = rounds.len();

    for round in rounds {
        let algo_round = Round(round);
        // Fetch the raw msgpack once: the Rust verifier decodes it, and
        // (when exporting) the very same bytes go to the Go helper so
        // both implementations authenticate byte-identical input.
        let raw = match client.get_block_raw(algo_round).await {
            Ok(b) => b,
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
                            rust_vote_present: None,
                        },
                    )?;
                }
                continue;
            }
        };
        let resp = match algo_codec::decode_block_response(&raw) {
            Ok(r) => r,
            Err(e) => {
                warn!(round = round, error = %e, "block decode failed — skipping");
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
                            rust_vote_present: None,
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
                            rust_vote_present: None,
                        },
                    )?;
                }
                continue;
            }
        };

        // (#470 §2) Is the Rust participant's vote in this certificate?
        let rust_vote_present = rust_account
            .as_ref()
            .map(|a| cert_contains_sender(&pair.certificate, a));
        if rust_vote_present == Some(true) {
            rust_vote_rounds.push(round);
        }

        // (#470 §2) Export the ledger facts Go's verifier will need.
        // A lookup failure here is reported but not fatal on its own —
        // the Rust-side authentication below is the primary gate, and
        // the Go helper reports a short export as missing coverage.
        if cli.export_go_input.is_some() {
            match build_go_verify_round(
                round,
                &raw,
                &pair,
                &bridge as &dyn LedgerReader,
                rust_account.as_ref(),
            ) {
                Ok(rec) => go_verify_rounds.push(rec),
                Err(e) => warn!(
                    round = round,
                    error = %e,
                    "could not build the go-verify export record for this round"
                ),
            }
        }

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
                    rust_vote_present,
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
                rust_account: cli.rust_account.clone(),
                rust_vote_rounds: rust_vote_rounds.len(),
                rust_vote_round_sample: rust_vote_rounds.iter().copied().take(64).collect(),
                min_rust_vote_rounds: cli.min_rust_vote_rounds,
            },
        )?;
    }

    // (#470 §2) Write the go-algorand-side verification bundle.
    if let Some(path) = &cli.export_go_input {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let exported = go_verify_rounds.len();
        let input = GoVerifyInput {
            rust_account: cli.rust_account.clone(),
            rounds: go_verify_rounds,
        };
        let f = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        serde_json::to_writer_pretty(std::io::BufWriter::new(f), &input)
            .with_context(|| format!("writing {}", path.display()))?;
        println!(
            "cert-crossverify: wrote go-verify input for {exported} round(s) to {}",
            path.display()
        );
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

    let mut rust_vote_gate_failed = false;
    if let Some(account) = &cli.rust_account {
        println!(
            "cert-crossverify: rust_account={account} vote present in {}/{} sampled certs \
             (gate: >= {})",
            rust_vote_rounds.len(),
            total_rounds - rounds_skipped_fetch,
            cli.min_rust_vote_rounds,
        );
        if rust_vote_rounds.len() < cli.min_rust_vote_rounds {
            rust_vote_gate_failed = true;
            println!(
                "FAIL: only {} of the sampled certificates contain a vote from {account}; \
                 wanted at least {}. The Rust node is following, not voting.",
                rust_vote_rounds.len(),
                cli.min_rust_vote_rounds
            );
        }
    }

    if rounds_failed > 0 || rust_vote_gate_failed {
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
