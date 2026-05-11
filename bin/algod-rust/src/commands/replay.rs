use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use algo_ledger::LedgerStore;
use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::{Address, Round};
use rusqlite::Connection;
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
    /// AVM execution stats (present when --avm-execute is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avm_stats: Option<AvmReportStats>,
}

/// AVM execution statistics for the JSON report.
#[derive(Debug, Serialize)]
pub struct AvmReportStats {
    pub app_calls_total: u64,
    pub app_calls_matching: u64,
    pub app_calls_mismatching: u64,
    pub app_calls_errored: u64,
    pub logicsig_total: u64,
    pub logicsig_passed: u64,
    pub logicsig_failed: u64,
    pub opcode_coverage: OpcodeCoverageReport,
    pub mismatch_categories: BTreeMap<String, u64>,
}

/// Opcode coverage statistics for the JSON report.
#[derive(Debug, Serialize)]
pub struct OpcodeCoverageReport {
    pub hit_count: usize,
    pub total_defined: usize,
    pub coverage_pct: f64,
    pub missed_opcodes: Vec<String>,
    pub hit_opcodes: Vec<String>,
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
                stxn.txn.txn_type.to_string()
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
            avm_stats: None,
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
/// close-to, asset sender/close-to, fee sink, rewards pool), including
/// addresses from EvalDelta inner transactions (recursively).
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
        collect_txn_addresses(stxn, &mut addrs);
    }

    addrs.into_iter().collect()
}

/// Extract address fields from a single signed transaction and, if it has an
/// EvalDelta with inner transactions, recurse into those as well.
fn collect_txn_addresses(stxn: &algo_types::SignedTransaction, addrs: &mut HashSet<Address>) {
    let txn = &stxn.txn;

    // Direct address fields on the transaction.
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
    // Application accounts array: these can be mutated by EvalDelta
    // and inner transactions.
    if let Some(ref accounts) = txn.accounts {
        for acct in accounts {
            if !acct.is_zero() {
                addrs.insert(*acct);
            }
        }
    }

    // Recursively walk EvalDelta inner transactions.
    if let Some(ref eval_delta_val) = stxn.eval_delta {
        match algo_ledger::parse_eval_delta(eval_delta_val) {
            Ok(ed) => {
                collect_eval_delta_addresses(&ed, addrs);
            }
            Err(e) => {
                warn!(
                    sender = %txn.sender.to_algorand_string(),
                    error = %e,
                    "failed to parse eval_delta for address collection; inner txn addresses may be missed"
                );
            }
        }
    }
}

/// Recursively extract addresses from a parsed EvalDelta's inner transactions.
fn collect_eval_delta_addresses(ed: &algo_ledger::EvalDelta, addrs: &mut HashSet<Address>) {
    if let Some(ref inner_txns) = ed.inner_txns {
        for inner_stx in inner_txns {
            collect_txn_addresses(inner_stx, addrs);
        }
    }
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
    trie: bool,
    compare_trie_db: Option<&Path>,
    avm_execute: bool,
) -> anyhow::Result<()> {
    if start > end {
        anyhow::bail!("invalid range: start ({start}) must be <= end ({end})");
    }

    let client = AlgodClient::new(algod_url, algod_token);

    // Open or create the SQLite ledger.
    // NOTE: On resume, in-memory leases from the previous session are lost.
    // This is acceptable because committed blocks are already validated —
    // lease violations cannot occur during replay of valid chain history.
    //
    // `db_path` is a ledger prefix (or legacy `.sqlite`-suffixed path);
    // existence is determined by the derived tracker file because the prefix
    // path itself does not exist as a file under the split layout.
    let db_exists = algo_ledger::ledger_exists(db_path);
    let mut store = algo_ledger::SqliteLedger::open(db_path)?;

    let effective_start = if db_exists {
        // Detect the cross-file split-commit gap before resuming. See
        // sqlite.rs `open_split` for the consistency model; replay is
        // strictly read-from-disk-and-apply, so refetching is out of
        // scope — we refuse to start and require the operator to recover.
        match store.reconcile_cross_file()? {
            algo_ledger::CrossFileState::Empty | algo_ledger::CrossFileState::Consistent { .. } => {
            }
            algo_ledger::CrossFileState::BlockBehind {
                tracker_round,
                block_max_round,
            } => {
                error!(
                    tracker_round,
                    block_max_round = ?block_max_round,
                    "cross-file split-commit gap detected: tracker advanced past blockdb.blocks. \
                     Refusing to resume — recover from a catchpoint or delete the ledger pair."
                );
                anyhow::bail!(
                    "ledger inconsistency: tracker at round {tracker_round} but blockdb.blocks \
                     stops at {block_max_round:?}. Recover from a catchpoint or delete the DB."
                );
            }
        }
        if let Some(last_round) = store.last_committed_round()? {
            let resume = last_round + 1;
            info!(
                last_committed = last_round,
                resuming_from = resume,
                "resuming stateful replay from existing DB"
            );
            resume
        } else {
            // DB exists but no committed round — stale/partial DB from a
            // previous aborted run. Delete and recreate to avoid stale state.
            warn!("existing DB has no committed round — recreating");
            drop(store);
            algo_ledger::remove_ledger_files(db_path)?;
            store = algo_ledger::SqliteLedger::open(db_path)?;
            load_genesis_into_store(&mut store, genesis_path)?;
            start
        }
    } else {
        load_genesis_into_store(&mut store, genesis_path)?;
        start
    };

    // Enable Merkle trie tracking before any blocks are applied.
    if trie {
        store.enable_trie();
        info!("Merkle trie tracking enabled");
    }

    if effective_start > end {
        info!(
            effective_start,
            end, "already past end round, nothing to replay"
        );
        return Ok(());
    }

    // Open Go's tracker.db for trie root conformance comparison (read-only).
    let go_trie_db = if let Some(go_db_path) = compare_trie_db {
        if !trie {
            anyhow::bail!("--compare-trie-db requires --trie to be enabled");
        }
        let conn =
            Connection::open_with_flags(go_db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        info!(path = %go_db_path.display(), "opened Go tracker.db for trie conformance");
        Some(conn)
    } else {
        None
    };

    info!(
        network,
        algod_url,
        effective_start,
        end,
        fail_fast,
        compare,
        sample_rate,
        trie,
        avm_execute,
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
    let mut total_skipped: u64 = 0;
    let mut trie_mismatches: u64 = 0;
    let mut last_trie_root: Option<[u8; 32]> = None;
    let mut last_trie_round: u64 = 0;
    let mut eval_delta_stats = algo_ledger::EvalDeltaStats::default();

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
                stxn.txn.txn_type.to_string()
            };
            *txn_type_counts.entry(ttype).or_insert(0) += 1;
            total_txns += 1;
        }

        // Apply block to ledger state.
        store.begin_block()?;
        let apply_result = if avm_execute {
            let (result, block_stats) = algo_ledger::apply_block_with_comparison(&mut store, block);
            // Merge per-block stats into running totals.
            eval_delta_stats += block_stats;
            result
        } else {
            algo_ledger::apply_block(&mut store, block)
        };
        match apply_result {
            Ok(()) => {
                // Read trie root before commit (finalize_trie_updates is called
                // inside apply_block; the root is logged at debug level there).
                // We log at info level here for CLI visibility.
                let trie_root: Option<[u8; 32]> = if trie {
                    store.finalize_trie_updates()
                } else {
                    None
                };

                store.commit_block()?;
                blocks_passed += 1;

                // Log trie root and remember last value for final comparison.
                if let Some(root) = trie_root {
                    let hex_root = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    info!(round = block.round.0, root = %hex_root, "trie root");
                    last_trie_root = Some(root);
                    last_trie_round = block.round.0;
                }
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
            let result = algo_conformance::compare_accounts(
                &touched,
                &store,
                cmp_client,
                round,
                sample_rate,
            )
            .await;

            total_skipped += result.skipped as u64;

            if !result.mismatches.is_empty() {
                for m in &result.mismatches {
                    warn!(
                        round = m.round,
                        addr = %m.address.to_algorand_string(),
                        field = %m.field,
                        expected = %m.expected,
                        actual = %m.actual,
                        "state mismatch"
                    );
                }
                total_mismatches += result.mismatches.len() as u64;
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

    // Conformance: compare final trie root against Go's tracker.db.
    // Go's catchpointstate stores a single trie root (not per-round), so we
    // can only meaningfully compare at the final round of the replay.
    if let (Some(root), Some(ref go_db)) = (last_trie_root, &go_trie_db) {
        let hex_root = root.iter().map(|b| format!("{b:02x}")).collect::<String>();
        match read_go_trie_root(go_db, last_trie_round) {
            Ok(Some(go_root)) => {
                if root == go_root {
                    info!(round = last_trie_round, "final trie root matches Go");
                } else {
                    let go_hex = go_root
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    warn!(
                        round = last_trie_round,
                        rust_root = %hex_root,
                        go_root = %go_hex,
                        "final trie root MISMATCH with Go"
                    );
                    trie_mismatches += 1;
                }
            }
            Ok(None) => {
                warn!(
                    round = last_trie_round,
                    "no trie root found in Go tracker.db"
                );
            }
            Err(e) => {
                warn!(
                    round = last_trie_round,
                    error = %e,
                    "failed to read Go trie root"
                );
            }
        }
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
        if total_skipped > 0 {
            println!("Accounts skipped: {total_skipped} (Go node errors)");
        }
    }
    if trie {
        println!("Trie enabled:     yes");
        if compare_trie_db.is_some() {
            println!("Trie mismatches:  {trie_mismatches}");
        }
    }
    println!("Elapsed:          {elapsed:.1}s ({blocks_per_sec:.1} blocks/sec)");

    if avm_execute {
        eval_delta_stats.print_summary();
    }

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
        let avm_stats = if avm_execute {
            Some(build_avm_report_stats(&eval_delta_stats))
        } else {
            None
        };
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
            avm_stats,
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

    if compare && total_mismatches > 0 {
        anyhow::bail!("{total_mismatches} state mismatches found during conformance comparison");
    }

    if compare && total_skipped > 0 {
        anyhow::bail!(
            "{total_skipped} accounts could not be compared (Go node errors) — conformance result is incomplete"
        );
    }

    if compare_trie_db.is_some() && trie_mismatches > 0 {
        anyhow::bail!("{trie_mismatches} trie root mismatches found during conformance comparison");
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

/// Read the Merkle trie root hash from Go's tracker.db for a given round.
///
/// Go's tracker.db stores trie-related state in several possible locations:
/// - `catchpointstate` table (key-value pairs including "trieRootHash")
/// - `merkletrienode` table (serialized trie nodes — would need full rebuild)
/// - `acctrounds` table (round tracking metadata)
///
/// We attempt to read from `catchpointstate` first, which stores the trie root
/// as a hex-encoded string under the key "accountsTrieRootHash" (or similar).
/// If that table/key is not found, we return None.
fn read_go_trie_root(conn: &Connection, _round: u64) -> anyhow::Result<Option<[u8; 32]>> {
    // Try catchpointstate table — Go stores various state hashes here.
    // The key for the accounts trie root is "balancesHash" in older versions
    // or may vary by Go version.
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    if tables.iter().any(|t| t == "catchpointstate") {
        // Try known key names for the trie root hash.
        let keys = [
            "balancesHash",
            "trieRootHash",
            "accountsTrieRootHash",
            "catchpointAccountHash",
        ];
        for key in &keys {
            let result: Option<Vec<u8>> = conn
                .prepare("SELECT val FROM catchpointstate WHERE id = ?1")
                .and_then(|mut stmt| {
                    stmt.query_row([key], |row| row.get::<_, Vec<u8>>(0))
                        .map(Some)
                })
                .unwrap_or(None);

            if let Some(val) = result {
                // The value may be raw 32 bytes or hex-encoded.
                if val.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&val);
                    return Ok(Some(hash));
                }
                // Try hex decoding.
                if let Ok(decoded) = hex_decode(&val) {
                    if decoded.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&decoded);
                        return Ok(Some(hash));
                    }
                }
            }
        }

        // Log available keys for debugging.
        let available: Vec<String> = conn
            .prepare("SELECT id FROM catchpointstate")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        warn!(
            keys = ?available,
            "catchpointstate table found but no recognized trie root key"
        );
    } else {
        warn!(
            available_tables = ?tables,
            "Go tracker.db does not contain catchpointstate table"
        );
    }

    Ok(None)
}

/// Simple hex decoder for ASCII hex strings stored as bytes.
fn hex_decode(input: &[u8]) -> Result<Vec<u8>, ()> {
    let s = std::str::from_utf8(input).map_err(|_| ())?;
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Convert EvalDeltaStats into a serializable AvmReportStats for JSON output.
fn build_avm_report_stats(stats: &algo_ledger::EvalDeltaStats) -> AvmReportStats {
    let cov = &stats.opcode_coverage;
    let opcode_coverage = OpcodeCoverageReport {
        hit_count: cov.hit_count(),
        total_defined: cov.total_defined(),
        coverage_pct: cov.coverage_pct(),
        missed_opcodes: cov
            .missed_opcodes()
            .iter()
            .map(|(byte, name)| format!("0x{byte:02x}:{name}"))
            .collect(),
        hit_opcodes: cov
            .hit_opcodes()
            .iter()
            .map(|(byte, name)| format!("0x{byte:02x}:{name}"))
            .collect(),
    };

    let mismatch_categories: BTreeMap<String, u64> = stats
        .mismatch_categories
        .iter()
        .map(|(cat, count)| (cat.to_string(), *count))
        .collect();

    AvmReportStats {
        app_calls_total: stats.app_calls_total,
        app_calls_matching: stats.app_calls_matching,
        app_calls_mismatching: stats.app_calls_mismatching,
        app_calls_errored: stats.app_calls_errored,
        logicsig_total: stats.logicsig_total,
        logicsig_passed: stats.logicsig_passed,
        logicsig_failed: stats.logicsig_failed,
        opcode_coverage,
        mismatch_categories,
    }
}
