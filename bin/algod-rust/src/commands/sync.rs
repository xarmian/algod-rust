use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use algo_ledger::{LedgerStore, SqliteLedger};
use algo_rest_client::{AlgodClient, BlockSource, ParallelBlockFetcher};
use algo_types::Round;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Run the sync command: fetch blocks in parallel and apply them to the ledger.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    genesis_path: Option<&Path>,
    db_path: &Path,
    start: u64,
    end: Option<u64>,
    concurrency: usize,
    avm_execute: bool,
    fail_fast: bool,
    trie: bool,
) -> anyhow::Result<()> {
    let client = Arc::new(AlgodClient::new(algod_url, algod_token));

    // Open or create the SQLite ledger.
    let db_exists = db_path.exists();
    let mut store = SqliteLedger::open(db_path)?;

    let effective_start = if db_exists {
        if let Some(last_round) = store.last_committed_round()? {
            let resume = last_round + 1;
            info!(
                last_committed = last_round,
                resuming_from = resume,
                "resuming sync from existing DB"
            );
            resume
        } else {
            // DB exists but no committed round — stale/partial DB.
            warn!("existing DB has no committed round — recreating");
            drop(store);
            std::fs::remove_file(db_path)?;
            store = SqliteLedger::open(db_path)?;
            if start == 0 {
                load_genesis_into_store(&mut store, genesis_path)?;
            } else {
                anyhow::bail!(
                    "cannot start sync at round {start} with a stale database; \
                     either use --start 0 with --genesis to initialize from genesis, \
                     or provide an existing DB that already has state"
                );
            }
            start
        }
    } else {
        if start == 0 {
            load_genesis_into_store(&mut store, genesis_path)?;
        } else {
            anyhow::bail!(
                "cannot start sync at round {start} with a fresh database; \
                 either use --start 0 with --genesis to initialize from genesis, \
                 or provide an existing DB that already has state"
            );
        }
        start
    };

    // Enable Merkle trie tracking if requested.
    if trie {
        store.enable_trie();
        info!("Merkle trie tracking enabled");
    }

    // Determine target round.
    let target = match end {
        Some(e) => e,
        None => {
            let status = client.get_status().await?;
            info!(
                last_round = status.last_round,
                "fetched chain tip from node"
            );
            status.last_round
        }
    };

    if effective_start > target {
        info!(
            effective_start,
            target, "already past target round, nothing to sync"
        );
        return Ok(());
    }

    info!(
        network,
        algod_url,
        effective_start,
        target,
        concurrency,
        avm_execute,
        trie,
        fail_fast,
        db = %db_path.display(),
        "starting parallel block sync"
    );

    // Create parallel fetcher.
    let fetcher = ParallelBlockFetcher::new(client as Arc<dyn BlockSource>, concurrency);
    let cancel = CancellationToken::new();

    // fetch_range uses half-open [start, end), so add 1 to include the target round.
    let mut rx = fetcher.fetch_range(Round(effective_start), Round(target + 1), cancel.clone());

    let timer = Instant::now();
    let mut blocks_applied: u64 = 0;
    let mut blocks_failed: u64 = 0;
    let mut total_txns: u64 = 0;
    let mut eval_delta_stats = algo_ledger::EvalDeltaStats::default();
    let progress_interval: u64 = 1000;
    let mut last_received_round: Option<u64> = None;

    while let Some((round, block_resp)) = rx.recv().await {
        last_received_round = Some(round.0);
        let block = &block_resp.block;

        // Count transactions.
        total_txns += block.payset.len() as u64;

        // Apply block to ledger.
        store.begin_block()?;
        let apply_result = if avm_execute {
            let (result, block_stats) = algo_ledger::apply_block_with_comparison(&mut store, block);
            eval_delta_stats += block_stats;
            result
        } else {
            algo_ledger::apply_block(&mut store, block)
        };

        match apply_result {
            Ok(()) => {
                if trie {
                    store.finalize_trie_updates();
                }
                store.commit_block()?;
                blocks_applied += 1;
            }
            Err(e) => {
                warn!(round = round.0, error = %e, "apply_block failed");
                let _ = store.rollback_block();
                blocks_failed += 1;
                if fail_fast {
                    error!(round = round.0, "fail-fast: stopping on apply failure");
                    cancel.cancel();
                    break;
                }
            }
        }

        // Progress logging.
        let blocks_done = blocks_applied + blocks_failed;
        if blocks_done % progress_interval == 0 || round.0 == target {
            let elapsed = timer.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                blocks_done as f64 / elapsed
            } else {
                0.0
            };
            info!(
                "Block {}/{} ({:.1}s, {:.1} blocks/sec)",
                round.0, target, elapsed, rate
            );
        }
    }

    // Check if the pipeline closed before we received the target round.
    // This distinguishes fetch failures from apply failures (which are tracked via blocks_failed).
    let pipeline_failed = match last_received_round {
        Some(r) if r >= target => false,
        _ if blocks_applied + blocks_failed == 0 && effective_start <= target => true,
        Some(_) => true, // last received round < target means pipeline stopped early
        None => effective_start <= target, // received nothing but had work to do
    };
    if pipeline_failed {
        error!("block fetch pipeline closed before reaching target round — sync incomplete");
        anyhow::bail!("block fetch pipeline failed");
    }

    let elapsed = timer.elapsed().as_secs_f64();
    let total_blocks = blocks_applied + blocks_failed;
    let blocks_per_sec = if elapsed > 0.0 {
        total_blocks as f64 / elapsed
    } else {
        0.0
    };

    // Print summary.
    println!("=== Sync Summary ===");
    println!("Network:          {network}");
    println!("Rounds:           {effective_start} - {target}");
    println!("Blocks applied:   {total_blocks} ({blocks_applied} passed, {blocks_failed} failed)");
    println!("Total txns:       {total_txns}");
    println!("Elapsed:          {elapsed:.1}s ({blocks_per_sec:.1} blocks/sec)");

    if trie {
        println!("Trie enabled:     yes");
    }

    if avm_execute {
        eval_delta_stats.print_summary();
    }

    if blocks_failed > 0 {
        anyhow::bail!("{blocks_failed} blocks failed apply");
    }

    Ok(())
}

/// Load genesis JSON and populate the store. Requires `--genesis` to be set.
fn load_genesis_into_store(
    store: &mut SqliteLedger,
    genesis_path: Option<&Path>,
) -> anyhow::Result<()> {
    let path = genesis_path.ok_or_else(|| {
        anyhow::anyhow!("--genesis is required when starting from round 0 without an existing DB")
    })?;
    let genesis_json = std::fs::read_to_string(path)?;
    let genesis = algo_ledger::parse_genesis_json(&genesis_json)?;
    algo_ledger::populate_store(store, &genesis)?;
    info!(genesis_path = %path.display(), "genesis loaded into ledger");
    Ok(())
}
