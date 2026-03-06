use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::{Address, Round};
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

        // Extract raw payset blobs for commitment verification.
        // On extraction failure, fall back to None (warn-only commitments).
        let raw_blobs = algo_codec::extract_raw_payset_blobs(&raw).ok();
        let raw_blobs_ref = raw_blobs.as_deref();

        // Validate
        let result = algo_validate::validate_block(
            block,
            prev_timestamp,
            &genesis_id,
            &genesis_hash,
            raw_blobs_ref,
        );

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

/// Extract the set of addresses "touched" by a block (sender, receiver,
/// close-to, asset sender/close-to, fee sink, rewards pool).
fn collect_touched_addresses(block: &algo_types::Block) -> Vec<Address> {
    let mut addrs = HashSet::new();

    // Fee sink and rewards pool are always touched.
    if !block.fee_sink.is_zero() {
        addrs.insert(block.fee_sink);
    }
    if !block.rewards_pool.is_zero() {
        addrs.insert(block.rewards_pool);
    }

    for stxn in &block.payset {
        let txn = &stxn.txn;
        if !txn.sender.is_zero() {
            addrs.insert(txn.sender);
        }
        if !txn.receiver.is_zero() {
            addrs.insert(txn.receiver);
        }
        if !txn.close_remainder_to.is_zero() {
            addrs.insert(txn.close_remainder_to);
        }
        if let Some(ref a) = txn.asset_sender {
            if !a.is_zero() {
                addrs.insert(*a);
            }
        }
        if let Some(ref a) = txn.asset_receiver {
            if !a.is_zero() {
                addrs.insert(*a);
            }
        }
        if let Some(ref a) = txn.asset_close_to {
            if !a.is_zero() {
                addrs.insert(*a);
            }
        }
        if let Some(ref a) = txn.freeze_account {
            if !a.is_zero() {
                addrs.insert(*a);
            }
        }
    }

    addrs.into_iter().collect()
}

/// Stateful replay: applies blocks to a ledger and optionally compares against
/// a Go node for conformance.
#[allow(clippy::too_many_arguments)]
pub async fn run_stateful(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    start: u64,
    end: u64,
    fail_fast: bool,
    report_path: Option<&Path>,
    genesis_path: Option<&Path>,
    compare: bool,
    compare_url: &str,
    compare_token: &str,
    sample_rate: u64,
    db_path: &Path,
) -> anyhow::Result<()> {
    if start > end {
        anyhow::bail!("invalid range: start ({start}) must be <= end ({end})");
    }

    let client = AlgodClient::new(algod_url, algod_token);

    // Open or create the SQLite ledger.
    let db_exists = db_path.exists();
    let mut store = algo_ledger::SqliteLedger::open(db_path)?;

    let effective_start = if db_exists {
        if let Some(last_round) = store.last_committed_round()? {
            let resume = last_round + 1;
            info!(
                last_committed = last_round,
                resuming_from = resume,
                "resuming stateful replay from existing DB"
            );
            resume
        } else {
            // DB exists but no committed round — treat as fresh.
            load_genesis_into_store(&mut store, genesis_path)?;
            start
        }
    } else {
        load_genesis_into_store(&mut store, genesis_path)?;
        start
    };

    if effective_start > end {
        info!(
            effective_start,
            end, "already past end round, nothing to replay"
        );
        return Ok(());
    }

    info!(
        network,
        algod_url,
        effective_start,
        end,
        fail_fast,
        compare,
        sample_rate,
        db = %db_path.display(),
        "starting stateful block replay"
    );

    let compare_client = if compare {
        Some(AlgodClient::new(compare_url, compare_token))
    } else {
        None
    };

    let timer = Instant::now();
    let mut blocks_passed: u64 = 0;
    let mut blocks_failed: u64 = 0;
    let mut total_txns: u64 = 0;
    let mut txn_type_counts: HashMap<String, u64> = HashMap::new();
    let mut failures: Vec<ReplayFailure> = Vec::new();
    let mut total_mismatches: u64 = 0;

    let mut round = effective_start;
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

        // Apply block to ledger state.
        store.begin_block()?;
        match algo_ledger::apply_block(&mut store, block) {
            Ok(()) => {
                store.commit_block()?;
                blocks_passed += 1;
            }
            Err(e) => {
                warn!(round, error = %e, "apply_block failed");
                let _ = store.rollback_block(); // discard partial state
                failures.push(ReplayFailure {
                    round,
                    errors: vec![format!("apply_block error: {e}")],
                });
                blocks_failed += 1;
                if fail_fast {
                    error!(round, "fail-fast: stopping on apply failure");
                    break;
                }
                round += 1;
                continue;
            }
        }

        // Conformance comparison against Go node.
        if let Some(ref cmp_client) = compare_client {
            let touched = collect_touched_addresses(block);
            let mismatches = algo_conformance::compare_accounts(
                &touched,
                &store,
                cmp_client,
                round,
                sample_rate,
            )
            .await;

            if !mismatches.is_empty() {
                for m in &mismatches {
                    warn!(
                        round = m.round,
                        addr = %m.address.to_algorand_string(),
                        field = %m.field,
                        expected = %m.expected,
                        actual = %m.actual,
                        "state mismatch"
                    );
                }
                total_mismatches += mismatches.len() as u64;
            }
        }

        // Progress logging every 10 blocks
        let blocks_done = round - effective_start + 1;
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
    println!("=== Stateful Replay Summary ===");
    println!("Network:          {network}");
    println!("Rounds:           {effective_start} - {end}");
    println!(
        "Blocks applied:   {blocks_validated} ({blocks_passed} passed, {blocks_failed} failed)"
    );
    println!("Total txns:       {total_txns}");
    if compare {
        println!("State mismatches: {total_mismatches}");
    }
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
            start_round: effective_start,
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
        info!(path = %path.display(), "stateful replay report written");
    }

    if blocks_failed > 0 {
        anyhow::bail!("{blocks_failed} blocks failed apply");
    }

    Ok(())
}

/// Load genesis JSON and populate the store. Requires `--genesis` to be set.
fn load_genesis_into_store(
    store: &mut algo_ledger::SqliteLedger,
    genesis_path: Option<&Path>,
) -> anyhow::Result<()> {
    let path = genesis_path.ok_or_else(|| {
        anyhow::anyhow!("--genesis is required for stateful replay without an existing DB")
    })?;
    let genesis_json = std::fs::read_to_string(path)?;
    let genesis = algo_ledger::parse_genesis_json(&genesis_json)?;
    algo_ledger::populate_store(store, &genesis)?;
    info!(genesis_path = %path.display(), "genesis loaded into ledger");
    Ok(())
}
