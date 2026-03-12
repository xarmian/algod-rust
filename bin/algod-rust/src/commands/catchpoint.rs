use std::io::Write;
use std::path::Path;
use std::time::Instant;

use algo_ledger::catchpoint::{
    import_catchpoint_file, parse_catchpoint_label, validate_post_import, verify_catchpoint,
};
use algo_rest_client::{CatchpointDownloader, DownloadProgress};
use rusqlite::Connection;
use tracing::{error, info, warn};

/// Run the catchpoint import subcommand.
///
/// Pipeline: download (optional) -> import -> verify -> download lookback -> reconstruct leases.
#[allow(clippy::too_many_arguments)]
pub async fn run_import(
    file_path: &Path,
    db_path: &Path,
    label: Option<&str>,
    reward_unit: u64,
    verify: bool,
) -> anyhow::Result<()> {
    let timer = Instant::now();

    // Step 1: Open database connection.
    let conn = Connection::open(db_path).map_err(|e| anyhow::anyhow!("open db: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| anyhow::anyhow!("set pragmas: {e}"))?;

    println!("=== Catchpoint Import ===");
    println!("File:     {}", file_path.display());
    println!("Database: {}", db_path.display());

    // Step 2: Extract header before import to get block_header_digest.
    let header = {
        let reader = algo_ledger::catchpoint::parser::open(file_path)
            .map_err(|e| anyhow::anyhow!("open catchpoint file: {e}"))?;
        let mut header = None;
        // Use an early-exit error to stop iterating after the header is found.
        // The header is always the first entry, so this avoids scanning the
        // entire (potentially multi-GB) catchpoint file just for the header.
        let result = reader.for_each(|entry| {
            if let algo_ledger::catchpoint::CatchpointEntry::Header(h) = entry {
                header = Some(h);
                // Return an error to stop iteration early (header found).
                return Err(algo_ledger::catchpoint::CatchpointError::IntegrityError(
                    "header_found_sentinel".to_string(),
                ));
            }
            Ok(())
        });
        // Ignore the sentinel error; propagate real errors only if no header was found.
        if header.is_none() {
            result.map_err(|e| anyhow::anyhow!("read catchpoint header: {e}"))?;
            anyhow::bail!("catchpoint file has no header");
        }
        header.unwrap()
    };

    let block_header_digest: [u8; 32] = if header.block_header_digest.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&header.block_header_digest);
        arr
    } else {
        anyhow::bail!(
            "block_header_digest has unexpected length: {} (expected 32)",
            header.block_header_digest.len()
        );
    };

    println!(
        "Round:    {} (balances), {} (blocks)",
        header.balances_round, header.blocks_round
    );
    println!("Accounts: {}", header.total_accounts);
    println!("Chunks:   {}", header.total_chunks);
    if !header.catchpoint.is_empty() {
        println!("Label:    {}", header.catchpoint);
    }

    // Step 3: Validate label if provided.
    if let Some(expected_label) = label {
        if !header.catchpoint.is_empty() && header.catchpoint != expected_label {
            anyhow::bail!(
                "provided label '{}' does not match file header label '{}'",
                expected_label,
                header.catchpoint
            );
        }
        let parsed = parse_catchpoint_label(expected_label)
            .map_err(|e| anyhow::anyhow!("invalid label: {e}"))?;
        info!(round = parsed.round, "label validated");
    }

    // Step 4: Import.
    println!("\nImporting...");
    let import_result = import_catchpoint_file(&conn, file_path, reward_unit)
        .map_err(|e| anyhow::anyhow!("import failed: {e}"))?;

    println!(
        "Import complete: {} accounts in {:.1}s",
        import_result.stats.accounts,
        import_result.duration.as_secs_f64()
    );

    // Step 5: Verify (if requested).
    if verify {
        println!("\nVerifying...");
        let verify_timer = Instant::now();
        let result = verify_catchpoint(&conn, &block_header_digest)
            .map_err(|e| anyhow::anyhow!("verification failed: {e}"))?;

        let verify_elapsed = verify_timer.elapsed();
        if result.success {
            println!("Verification PASSED ({:.1}s)", verify_elapsed.as_secs_f64());
            println!("  Label:    {}", result.computed_label);
            println!("  Accounts: {}", result.accounts_count);
            let trie_hex: String = result
                .trie_root
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("  Trie root: {trie_hex}...");
        } else {
            error!("Verification FAILED");
            println!("  Expected: {}", result.expected_label);
            println!("  Computed: {}", result.computed_label);
            anyhow::bail!("catchpoint verification failed");
        }
    }

    // Step 6: Post-import validation.
    println!("\nRunning post-import validation...");
    let warnings = validate_post_import(&conn, import_result.round)
        .map_err(|e| anyhow::anyhow!("post-import validation error: {e}"))?;

    if warnings.is_empty() {
        println!("Post-import validation: all checks passed");
    } else {
        println!("Post-import validation: {} warning(s)", warnings.len());
        for w in &warnings {
            warn!(category = %w.category, "{}", w.message);
            println!("  [{}] {}", w.category, w.message);
        }
    }

    // Step 7: Initialize chain metadata from catchpoint.
    //
    // The catchpoint file header does not contain genesis_id, genesis_hash,
    // or protocol version. We extract the protocol from the most recent
    // onlineroundparamstail entry (which encodes the protocol as "proto").
    // Genesis info is not available from the catchpoint file and must be
    // provided separately for full node startup.
    {
        let protocol: Option<String> = conn
            .query_row(
                "SELECT data FROM onlineroundparamstail ORDER BY rnd DESC LIMIT 1",
                [],
                |row| {
                    let data: Vec<u8> = row.get(0)?;
                    Ok(data)
                },
            )
            .ok()
            .and_then(|data| {
                // Extract the "proto" field from the msgpack-encoded OnlineRoundParamsData.
                let val = rmpv::decode::read_value(&mut &data[..]).ok()?;
                if let rmpv::Value::Map(map) = val {
                    for (k, v) in &map {
                        if let rmpv::Value::String(s) = k {
                            if s.as_str() == Some("proto") {
                                if let rmpv::Value::String(proto) = v {
                                    return proto.as_str().map(|s| s.to_string());
                                }
                            }
                        }
                    }
                }
                None
            });

        // Derive txn_counter from the maximum creatable ID in the imported
        // assetcreators table. Asset/app IDs are derived as txn_counter + 1,
        // so the max creatable ID equals the txn_counter at the time of its
        // creation. This is a safe lower bound that prevents ID collisions
        // in the first post-import block.
        //
        // The catchpoint file header (Go's CatchpointFileHeader) does not
        // carry TxnCounter — Go-algorand restores it from lookback block
        // headers. Until lookback download is implemented, this derivation
        // is the best available approximation.
        let txn_counter: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(asset), 0) FROM assetcreators",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if txn_counter > 0 {
            info!(txn_counter, "derived txn_counter from max creatable ID");
            println!(
                "  txn_counter: {} (derived from max creatable ID)",
                txn_counter
            );
        } else {
            warn!("txn_counter is 0 — no creatables found in assetcreators table");
            println!("  txn_counter: 0 (no creatables found; first block with asset/app creation may fail)");
        }

        let rewards_level = header.totals.rewards_level;

        let proto_str = protocol.as_deref().unwrap_or("");
        // Use a zeroed genesis hash as placeholder — the caller should
        // provide the real genesis info via a separate init step if needed.
        let empty_genesis_hash = [0u8; 32];
        if let Err(e) = algo_ledger::sqlite::initialize_meta_from_catchpoint(
            &conn,
            import_result.round,
            "", // genesis_id not available from catchpoint file
            &empty_genesis_hash,
            proto_str,
            txn_counter,
            rewards_level,
        ) {
            warn!("failed to initialize chain meta: {e}");
            println!("Warning: chain meta initialization failed: {e}");
            println!("  genesis_id and genesis_hash must be set separately for full node startup");
        } else {
            info!(
                round = import_result.round,
                protocol = proto_str,
                txn_counter,
                rewards_level,
                "chain meta initialized from catchpoint"
            );
        }
    }

    // Step 8: Warn about lease table reconstruction.
    //
    // The import pipeline does not download lookback blocks or reconstruct
    // the lease table. Without these steps, the node cannot safely validate
    // lease constraints for new blocks that reference leases created in
    // the lookback window (up to MaxTxnLife rounds before the catchpoint).
    //
    // In go-algorand, the catchpoint restore process downloads lookback
    // blocks and replays them to rebuild the lease table and the txtail.
    // Our import path does not yet do this automatically because it
    // requires network access (a block source / algod URL).
    println!();
    println!("WARNING: Lease table not reconstructed after catchpoint import.");
    println!("  The node cannot safely process new blocks until lookback blocks");
    println!("  are downloaded and leases are rebuilt. To complete the import:");
    println!();
    println!("  1. Run `algod-rust sync` from the catchpoint round to download");
    println!("     lookback blocks and reconstruct the lease table, OR");
    println!("  2. If resuming from a trusted state, ensure no active leases");
    println!("     exist in the lookback window (MaxTxnLife = 1000 rounds).");
    println!();
    println!("  Without this step, blocks containing lease-constrained transactions");
    println!("  may be incorrectly accepted or rejected.");
    warn!("lease table not reconstructed — lookback block download required before processing new blocks");

    let total_elapsed = timer.elapsed();
    println!("=== Done ({:.1}s total) ===", total_elapsed.as_secs_f64());

    Ok(())
}

/// Run the catchpoint verify subcommand (verify an already-imported database).
pub async fn run_verify(db_path: &Path, file_path: Option<&Path>) -> anyhow::Result<()> {
    let conn = Connection::open(db_path).map_err(|e| anyhow::anyhow!("open db: {e}"))?;

    println!("=== Catchpoint Verify ===");
    println!("Database: {}", db_path.display());

    // We need the block_header_digest. If a catchpoint file is provided, extract
    // it from the header. Otherwise, error out.
    let block_header_digest: [u8; 32] = if let Some(path) = file_path {
        let reader = algo_ledger::catchpoint::parser::open(path)
            .map_err(|e| anyhow::anyhow!("open catchpoint file: {e}"))?;
        let mut header = None;
        let result = reader.for_each(|entry| {
            if let algo_ledger::catchpoint::CatchpointEntry::Header(h) = entry {
                header = Some(h);
                return Err(algo_ledger::catchpoint::CatchpointError::IntegrityError(
                    "header_found_sentinel".to_string(),
                ));
            }
            Ok(())
        });
        if header.is_none() {
            result.map_err(|e| anyhow::anyhow!("read catchpoint header: {e}"))?;
            anyhow::bail!("catchpoint file has no header");
        }
        let h = header.unwrap();
        if h.block_header_digest.len() != 32 {
            anyhow::bail!(
                "block_header_digest has unexpected length: {}",
                h.block_header_digest.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h.block_header_digest);
        arr
    } else {
        anyhow::bail!("--file is required for verification (provides the block header digest)");
    };

    let timer = Instant::now();
    let result = verify_catchpoint(&conn, &block_header_digest)
        .map_err(|e| anyhow::anyhow!("verification failed: {e}"))?;

    let elapsed = timer.elapsed();
    if result.success {
        println!("Verification PASSED ({:.1}s)", elapsed.as_secs_f64());
        println!("  Label:    {}", result.computed_label);
        println!("  Accounts: {}", result.accounts_count);
    } else {
        println!("Verification FAILED ({:.1}s)", elapsed.as_secs_f64());
        println!("  Expected: {}", result.expected_label);
        println!("  Computed: {}", result.computed_label);
        anyhow::bail!("catchpoint verification failed");
    }

    Ok(())
}

/// Run the catchpoint download subcommand.
pub async fn run_download(
    algod_url: &str,
    algod_token: &str,
    genesis_id: &str,
    round: u64,
    output: &Path,
) -> anyhow::Result<()> {
    println!("=== Catchpoint Download ===");
    println!("URL:        {algod_url}");
    println!("Genesis ID: {genesis_id}");
    println!("Round:      {round}");
    println!("Output:     {}", output.display());

    let downloader = CatchpointDownloader::new(algod_url, algod_token);

    let timer = Instant::now();
    downloader
        .download(
            genesis_id,
            round,
            output,
            Some(|progress: DownloadProgress| {
                if let Some(total) = progress.total_bytes {
                    let pct = (progress.bytes_downloaded as f64 / total as f64) * 100.0;
                    print!(
                        "\rDownloading... {:.1}% ({} / {} bytes)",
                        pct, progress.bytes_downloaded, total
                    );
                } else {
                    print!("\rDownloading... {} bytes", progress.bytes_downloaded);
                }
                let _ = std::io::stdout().flush();
            }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;

    println!(); // newline after progress
    let elapsed = timer.elapsed();
    println!(
        "Download complete ({:.1}s): {}",
        elapsed.as_secs_f64(),
        output.display()
    );

    Ok(())
}
