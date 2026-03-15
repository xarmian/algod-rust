use std::collections::HashMap;
use std::path::Path;

use algo_bench::output::load_comparison;
use algo_bench::table::{render_markdown, render_terminal};
use algo_bench::{BenchConfig, BenchRun, Implementation, MetricsCollector};
use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::Round;
use tracing::{info, warn};

/// Run a benchmark of mainnet block replay (decode + validate throughput).
pub async fn run_replay(
    algod_url: &str,
    algod_token: &str,
    start_round: u64,
    count: u64,
    output: &Path,
) -> anyhow::Result<()> {
    if count == 0 {
        anyhow::bail!("--count must be > 0");
    }

    let end_round = start_round + count - 1;

    info!(
        algod_url,
        start_round, end_round, count, "starting bench replay"
    );

    let client = AlgodClient::new(algod_url, algod_token);

    // Fetch genesis info and prev_timestamp from the block before start.
    let mut prev_timestamp: Option<i64> = None;
    let (genesis_id, genesis_hash) = if start_round > 1 {
        let prev_raw = client.get_block_raw(Round(start_round - 1)).await?;
        let prev_br = algo_codec::decode_block_response(&prev_raw)?;
        prev_timestamp = Some(prev_br.block.timestamp);
        let hash: [u8; 32] = prev_br
            .block
            .genesis_hash
            .as_ref()
            .try_into()
            .expect("genesis hash must be 32 bytes");
        (prev_br.block.genesis_id.clone(), hash)
    } else {
        let first_raw = client.get_block_raw(Round(start_round)).await?;
        let first_br = algo_codec::decode_block_response(&first_raw)?;
        let hash: [u8; 32] = first_br
            .block
            .genesis_hash
            .as_ref()
            .try_into()
            .expect("genesis hash must be 32 bytes");
        (first_br.block.genesis_id.clone(), hash)
    };

    // Start metrics collection.
    let collector = MetricsCollector::new();

    let mut blocks_processed: u64 = 0;
    let mut total_txns: u64 = 0;

    for round in start_round..=end_round {
        // Fetch block.
        let raw = client.get_block_raw(Round(round)).await?;

        // Decode block.
        let block_resp = algo_codec::decode_block_response(&raw)?;
        let block = &block_resp.block;

        // Count transactions.
        total_txns += block.payset.len() as u64;

        // Extract raw payset blobs for commitment verification.
        let raw_blobs = algo_codec::extract_raw_payset_blobs(&raw).ok();
        let raw_blobs_ref = raw_blobs.as_deref();

        // Validate block (stateless).
        let result = algo_validate::validate_block(
            block,
            prev_timestamp,
            &genesis_id,
            &genesis_hash,
            raw_blobs_ref,
        );
        if !result.is_valid {
            warn!(
                round,
                errors = ?result.errors,
                "block validation failed with {} error(s)",
                result.errors.len()
            );
        }

        prev_timestamp = Some(block.timestamp);
        blocks_processed += 1;

        // Progress logging every 10 blocks.
        if blocks_processed % 10 == 0 || round == end_round {
            info!("Block {round}/{end_round} ({blocks_processed}/{count} done)");
        }
    }

    // Finish metrics collection.
    let mut metrics = collector.finish();

    let blocks_per_sec = if metrics.wall_clock_secs > 0.0 {
        blocks_processed as f64 / metrics.wall_clock_secs
    } else {
        0.0
    };
    let txns_per_sec = if metrics.wall_clock_secs > 0.0 {
        total_txns as f64 / metrics.wall_clock_secs
    } else {
        0.0
    };
    metrics.blocks_per_sec = Some(blocks_per_sec);
    metrics.txns_per_sec = Some(txns_per_sec);

    let run = BenchRun {
        scenario: "block-replay".to_string(),
        implementation: Implementation::Rust,
        metrics,
        timestamp: chrono::Utc::now().to_rfc3339(),
        git_sha: algo_bench::metrics::git_sha(),
        config: BenchConfig {
            block_range: Some(format!("{}-{}", start_round, end_round)),
            block_count: Some(count),
            duration_secs: None,
            custom: HashMap::new(),
        },
    };

    // Save JSON output.
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    algo_bench::output::save_run(&run, output)
        .map_err(|e| anyhow::anyhow!("failed to save bench run: {e}"))?;
    info!(path = %output.display(), "benchmark results saved");

    // Print terminal summary.
    println!("=== Bench Replay Summary ===");
    println!("Scenario:     {}", run.scenario);
    println!("Blocks:       {blocks_processed}");
    println!("Transactions: {total_txns}");
    println!("Elapsed:      {:.1}s", run.metrics.wall_clock_secs);
    println!("Blocks/sec:   {blocks_per_sec:.1}");
    println!("Txns/sec:     {txns_per_sec:.1}");
    println!(
        "Peak RSS:     {}",
        algo_bench::format_bytes(run.metrics.peak_rss_bytes)
    );
    println!("Avg CPU:      {:.1}%", run.metrics.avg_cpu_pct);
    println!("Output:       {}", output.display());

    Ok(())
}

/// Compare Rust and Go benchmark results side by side.
pub fn run_compare(rust_json: &Path, go_json: &Path, markdown: bool) -> anyhow::Result<()> {
    let comparison = load_comparison(rust_json, go_json)
        .map_err(|e| anyhow::anyhow!("failed to load benchmark results: {e}"))?;

    let output = if markdown {
        render_markdown(&comparison)
    } else {
        render_terminal(&comparison)
    };

    println!("{output}");

    Ok(())
}
