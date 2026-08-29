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

//! `algo-fork-detector` binary (PLAN-32 / TASK-88).
//!
//! Polls `/v2/blocks/{r}` across a set of algod REST nodes, computes each
//! block's digest locally, and asserts that every reporting node sees the
//! same digest for each round in a range. Exits non-zero on any fork
//! finding (or any insufficient-coverage / fetch-error finding with
//! `--strict`).
//!
//! Usage (see `--help` for all knobs):
//!
//! ```text
//! algo-fork-detector \
//!     --nodes go-node-1=http://127.0.0.1:4001,\
//!             go-node-2=http://127.0.0.1:4002,\
//!             go-node-3=http://127.0.0.1:4003 \
//!     --from-round 1 --to-round 200 \
//!     --token-file ops/mixed-cluster/netroot/Node1/algod.token
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use algo_codec::compute_block_digest;
use algo_fork_detector::{
    aggregate_findings, compare_round, DigestByNode, FindingKind, NodeEndpoint, RoundVerdict,
};
use algo_rest_client::{AlgodClient, BlockSource, ClientConfig};
use algo_types::Round;
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::Serialize;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "algo-fork-detector",
    about = "PLAN-32 / TASK-88 fork detector for the mixed-cluster harness"
)]
struct Cli {
    /// Comma-separated list of `name=base_url` pairs identifying the REST
    /// nodes to poll. Names appear in the output; base URLs must be full
    /// http(s):// URLs.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    nodes: Vec<String>,

    /// First round to check (inclusive). Use 1 to start from genesis+1.
    #[arg(long)]
    from_round: u64,

    /// Last round to check (inclusive).
    #[arg(long)]
    to_round: u64,

    /// Path to a file containing the API token (matches node's algod.token).
    /// Either `--token-file` or `--token` is required.
    #[arg(long, conflicts_with = "token")]
    token_file: Option<PathBuf>,

    /// API token value (alternative to --token-file).
    #[arg(long)]
    token: Option<String>,

    /// Allow the run to exit 0 even when some nodes failed to return a
    /// block for a round (FetchError) or too few nodes reported
    /// (InsufficientCoverage). The detector defaults to failing on
    /// these because a node that 404s every round should not produce
    /// a green verification just because the other nodes happen to
    /// agree among themselves. Use with care (e.g. when one node is
    /// known offline for maintenance).
    #[arg(long)]
    allow_degraded: bool,

    /// Emit the full verdicts list (one record per round) as JSONL to this
    /// path. Useful for feeding the output into downstream analysis. If
    /// unset, only the summary goes to stdout.
    #[arg(long)]
    jsonl_out: Option<PathBuf>,

    /// Per-request timeout in seconds (default: 10).
    #[arg(long, default_value_t = 10)]
    timeout_s: u64,

    /// Verbose logging (RUST_LOG-style): info, debug, trace.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsonlRecord {
    RoundVerdict {
        round: u64,
        verdict: &'static str,
        digests: BTreeMap<String, String>,
    },
    Finding {
        round: u64,
        // Renamed from `kind` so it doesn't collide with serde's external
        // tag (also named `kind`). The serialized shape is still
        // `{"kind":"finding", "finding_kind":"fork", ...}`.
        finding_kind: &'static str,
        detail: String,
    },
    Summary {
        from_round: u64,
        to_round: u64,
        total_rounds: u64,
        fork_findings: usize,
        insufficient_findings: usize,
        fetch_error_findings: usize,
        nodes_polled: Vec<String>,
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

fn parse_nodes(specs: &[String]) -> Result<Vec<(String, String)>> {
    if specs.is_empty() {
        bail!("--nodes must specify at least one name=url pair");
    }
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let (name, url) = s
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid --nodes entry {s:?}; expected 'name=url'"))?;
        let name = name.trim();
        let url = url.trim();
        if name.is_empty() {
            bail!("node name is empty in entry {s:?}");
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            bail!("node URL {url:?} must start with http:// or https://");
        }
        out.push((name.to_string(), url.to_string()));
    }
    Ok(out)
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

async fn fetch_digest(
    client: &AlgodClient,
    round: Round,
    node_name: &str,
) -> Result<Option<algo_types::Digest>> {
    // BlockSource provides an async get_block returning BlockResponse.
    match client.get_block(round).await {
        Ok(resp) => {
            let digest = compute_block_digest(&resp.block);
            debug!(node = %node_name, round = %round, "fetched block");
            Ok(Some(digest))
        }
        Err(e) => {
            // Node may not have the round yet — surface as None so the
            // caller can classify (FetchError). A 404 for a round past
            // the node's tip is still a fetch error worth noting; the
            // CLI decides via --strict whether it fails the run.
            warn!(node = %node_name, round = %round, error = %e, "block fetch failed");
            Ok(None)
        }
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
    let nodes_spec = parse_nodes(&cli.nodes)?;
    let token = load_token(&cli)?;

    // Build a client per node. ClientConfig shared.
    let config = ClientConfig {
        timeout: Duration::from_secs(cli.timeout_s),
        ..ClientConfig::default()
    };
    let nodes: Vec<(NodeEndpoint, Arc<AlgodClient>)> = nodes_spec
        .into_iter()
        .map(|(name, url)| {
            let client = Arc::new(AlgodClient::with_config(
                url.clone(),
                token.clone(),
                config.clone(),
            ));
            (
                NodeEndpoint {
                    name,
                    base_url: url,
                    token: token.clone(),
                },
                client,
            )
        })
        .collect();

    info!(
        "polling {} nodes for rounds {}..={}",
        nodes.len(),
        cli.from_round,
        cli.to_round
    );

    // Prepare JSONL output file if requested.
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

    // Fetch failures accumulate here with the specific (round, node)
    // pair so aggregate_findings can turn them into proper FetchError
    // findings. Silently collapsing fetches into None (as a previous
    // version did) lets a node that 404s every round produce a green
    // verification when the two surviving nodes happen to agree.
    let mut fetch_failures: Vec<(u64, String)> = Vec::new();
    let mut round_verdicts: Vec<(u64, RoundVerdict)> = Vec::new();

    for r in cli.from_round..=cli.to_round {
        let round = Round(r);

        // Fetch in parallel across nodes for this round.
        let mut handles = Vec::with_capacity(nodes.len());
        for (endpoint, client) in &nodes {
            let name = endpoint.name.clone();
            let client = Arc::clone(client);
            handles.push(tokio::spawn(async move {
                let d = fetch_digest(client.as_ref(), round, &name).await;
                (name, d)
            }));
        }

        let mut by_node = DigestByNode::new();
        for h in handles {
            match h.await {
                Ok((name, Ok(Some(digest)))) => {
                    by_node.insert(name, digest);
                }
                Ok((name, Ok(None))) => {
                    fetch_failures.push((r, name));
                }
                Ok((name, Err(e))) => {
                    warn!(node = %name, round = %round, error = %e, "fetch task returned error");
                    fetch_failures.push((r, name));
                }
                Err(join_err) => {
                    // Panic / cancellation — surface under a synthetic
                    // "<task>" node name so the caller sees *something*.
                    error!(error = %join_err, "fetch task panicked or was cancelled");
                    fetch_failures.push((r, format!("<task-error:{join_err}>")));
                }
            }
        }

        let verdict = compare_round(&by_node);

        if let Some(w) = jsonl_writer.as_mut() {
            let digests: BTreeMap<String, String> = by_node
                .iter()
                .map(|(n, d)| (n.clone(), hex::encode(d.as_bytes())))
                .collect();
            let label = match &verdict {
                RoundVerdict::Agreed { .. } => "agreed",
                RoundVerdict::Forked { .. } => "forked",
                RoundVerdict::Insufficient { .. } => "insufficient",
            };
            write_jsonl(
                w,
                &JsonlRecord::RoundVerdict {
                    round: r,
                    verdict: label,
                    digests,
                },
            )?;
        }

        round_verdicts.push((r, verdict));
    }

    let findings = aggregate_findings(round_verdicts, fetch_failures.iter().cloned());
    let fork_count = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Fork)
        .count();
    let insufficient_count = findings
        .iter()
        .filter(|f| f.kind == FindingKind::InsufficientCoverage)
        .count();
    let fetch_error_count = findings
        .iter()
        .filter(|f| f.kind == FindingKind::FetchError)
        .count();

    // Summary to stdout — human-readable.
    println!(
        "fork-detector: rounds {}..={} ({} total), nodes {} — forks={} insufficient={} fetch_errors={}",
        cli.from_round,
        cli.to_round,
        cli.to_round - cli.from_round + 1,
        nodes.len(),
        fork_count,
        insufficient_count,
        fetch_error_count
    );
    for f in &findings {
        let tag = match f.kind {
            FindingKind::Fork => "FORK",
            FindingKind::InsufficientCoverage => "INSUFFICIENT",
            FindingKind::FetchError => "FETCH_ERROR",
        };
        println!("  [{tag}] round={} {}", f.round, f.detail);
    }

    // Summary record at end of JSONL.
    if let Some(mut w) = jsonl_writer.take() {
        for f in &findings {
            let kind_str = match f.kind {
                FindingKind::Fork => "fork",
                FindingKind::InsufficientCoverage => "insufficient_coverage",
                FindingKind::FetchError => "fetch_error",
            };
            write_jsonl(
                &mut w,
                &JsonlRecord::Finding {
                    round: f.round,
                    finding_kind: kind_str,
                    detail: f.detail.clone(),
                },
            )?;
        }
        write_jsonl(
            &mut w,
            &JsonlRecord::Summary {
                from_round: cli.from_round,
                to_round: cli.to_round,
                total_rounds: cli.to_round - cli.from_round + 1,
                fork_findings: fork_count,
                insufficient_findings: insufficient_count,
                fetch_error_findings: fetch_error_count,
                nodes_polled: nodes.iter().map(|(e, _)| e.name.clone()).collect(),
            },
        )?;
    }

    // Exit code selection. Forks are always fatal (exit 2). Coverage
    // problems (fetch errors / insufficient) default to fatal (exit 1)
    // so a node that silently 404s every round can't be masked by the
    // surviving nodes agreeing; `--allow-degraded` opts out.
    if fork_count > 0 {
        return Ok(2);
    }
    if !cli.allow_degraded && (insufficient_count > 0 || fetch_error_count > 0) {
        return Ok(1);
    }
    Ok(0)
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
