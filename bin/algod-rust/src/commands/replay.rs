use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::Round;
use serde::Serialize;
use tracing::{error, info, warn};

/// Summary report for a replay run.
#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub network: String,
    pub start_round: u64,
    pub end_round: u64,
    pub blocks_validated: u64,
    pub blocks_passed: u64,
    pub blocks_failed: u64,
    pub total_txns: u64,
    pub txn_type_counts: HashMap<String, u64>,
    pub failures: Vec<ReplayFailure>,
    pub elapsed_secs: f64,
    pub blocks_per_sec: f64,
}

#[derive(Debug, Serialize)]
pub struct ReplayFailure {
    pub round: u64,
    pub errors: Vec<String>,
}

pub async fn run(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    start: u64,
    end: u64,
    fail_fast: bool,
    report_path: Option<&Path>,
) -> anyhow::Result<()> {
    if start > end {
        anyhow::bail!("invalid range: start ({start}) must be <= end ({end})");
    }

    let client = AlgodClient::new(algod_url, algod_token);

    info!(
        network,
        algod_url, start, end, fail_fast, "starting block replay"
    );

    // Fetch genesis info and prev_timestamp from the block before start.
    let mut prev_timestamp: Option<i64> = None;
    let (genesis_id, genesis_hash) = if start > 1 {
        let prev_raw = client.get_block_raw(Round(start - 1)).await?;
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
        let first_raw = client.get_block_raw(Round(start)).await?;
        let first_br = algo_codec::decode_block_response(&first_raw)?;
        let hash: [u8; 32] = first_br
            .block
            .genesis_hash
            .as_ref()
            .try_into()
            .expect("genesis hash must be 32 bytes");
        (first_br.block.genesis_id.clone(), hash)
    };

    let timer = Instant::now();
    let mut blocks_passed: u64 = 0;
    let mut blocks_failed: u64 = 0;
    let mut total_txns: u64 = 0;
    let mut txn_type_counts: HashMap<String, u64> = HashMap::new();
    let mut failures: Vec<ReplayFailure> = Vec::new();

    let mut round = start;
    while round <= end {
        // Fetch and decode
        let raw = match client.get_block_raw(Round(round)).await {
            Ok(r) => r,
            Err(e) => {
                warn!(round, error = %e, "failed to fetch block");
                failures.push(ReplayFailure {
                    round,
                    errors: vec![format!("fetch error: {e}")],
                });
                blocks_failed += 1;
                if fail_fast {
                    error!(round, "fail-fast: stopping on fetch failure");
                    break;
                }
                // Clear prev_timestamp so the next block doesn't get a false
                // TimestampTooNew error from comparing non-adjacent rounds.
                prev_timestamp = None;
                round += 1;
                continue;
            }
        };

        let block_resp = match algo_codec::decode_block_response(&raw) {
            Ok(br) => br,
            Err(e) => {
                warn!(round, error = %e, "failed to decode block");
                failures.push(ReplayFailure {
                    round,
                    errors: vec![format!("decode error: {e}")],
                });
                blocks_failed += 1;
                if fail_fast {
                    error!(round, "fail-fast: stopping on decode failure");
                    break;
                }
                prev_timestamp = None;
                round += 1;
                continue;
            }
        };

        let block = &block_resp.block;

        // Count txn types
        for stxn in &block.payset {
            let ttype = if stxn.txn.txn_type.is_empty() {
                "unknown".to_string()
            } else {
                stxn.txn.txn_type.clone()
            };
            *txn_type_counts.entry(ttype).or_insert(0) += 1;
            total_txns += 1;
        }

        // Validate
        let result =
            algo_validate::validate_block(block, prev_timestamp, &genesis_id, &genesis_hash);

        if result.is_valid {
            blocks_passed += 1;
        } else {
            let errs: Vec<String> = result.errors.iter().map(|e| e.to_string()).collect();
            failures.push(ReplayFailure {
                round,
                errors: errs,
            });
            blocks_failed += 1;
            if fail_fast {
                error!(round, "fail-fast: stopping on validation failure");
                break;
            }
        }

        // Update prev_timestamp for next block
        prev_timestamp = Some(block.timestamp);

        // Progress logging every 10 blocks
        let blocks_done = round - start + 1;
        if blocks_done % 10 == 0 || round == end {
            let elapsed = timer.elapsed().as_secs_f64();
            let rate = blocks_done as f64 / elapsed;
            info!("Block {round}/{end} ({elapsed:.1}s, {rate:.1} blocks/sec)");
        }

        round += 1;
    }

    let elapsed = timer.elapsed().as_secs_f64();
    let blocks_validated = blocks_passed + blocks_failed;
    let blocks_per_sec = if elapsed > 0.0 {
        blocks_validated as f64 / elapsed
    } else {
        0.0
    };

    // Print summary
    println!("=== Replay Summary ===");
    println!("Network:          {network}");
    println!("Rounds:           {start} - {end}");
    println!(
        "Blocks validated: {blocks_validated} ({blocks_passed} passed, {blocks_failed} failed)"
    );
    println!("Total txns:       {total_txns}");
    println!("Elapsed:          {elapsed:.1}s ({blocks_per_sec:.1} blocks/sec)");

    if !txn_type_counts.is_empty() {
        println!("\nTransaction type coverage:");
        let mut types: Vec<_> = txn_type_counts.iter().collect();
        types.sort_by_key(|(k, _)| (*k).clone());
        for (ttype, count) in &types {
            println!("  {ttype:<10} {count}");
        }
    }

    if !failures.is_empty() {
        println!("\nFailures ({} blocks):", failures.len());
        for f in &failures {
            println!("  Round {}: {} error(s)", f.round, f.errors.len());
            for e in &f.errors {
                println!("    - {e}");
            }
        }
    }

    // Write report if requested
    if let Some(path) = report_path {
        let report = ReplayReport {
            network: network.to_string(),
            start_round: start,
            end_round: end,
            blocks_validated,
            blocks_passed,
            blocks_failed,
            total_txns,
            txn_type_counts,
            failures,
            elapsed_secs: elapsed,
            blocks_per_sec,
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
        info!(path = %path.display(), "replay report written");
    }

    if blocks_failed > 0 {
        anyhow::bail!("{blocks_failed} blocks failed validation");
    }

    Ok(())
}
