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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use algo_ledger::catchpoint::{
    export_catchpoint_file, import_catchpoint_file, parse_catchpoint_label, validate_post_import,
    verify_catchpoint, ExportOptions,
};
use algo_ledger::open_ledger_connection_with_sync_mode;
use algo_rest_client::{CatchpointDownloadConfig, CatchpointDownloader, DownloadProgress};
use tracing::{error, info, warn};

/// Load `<data_dir>/config.json` (go-algorand `config.Local` equivalent,
/// issue #754/epic #745), falling back to fully-materialized go-matching
/// defaults when `data_dir` is `None` or its `config.json` fails to load.
/// Mirrors the pattern established for `participate` (issue #748).
fn load_node_config(data_dir: Option<&Path>) -> algo_config::Local {
    match data_dir {
        Some(dir) => match algo_config::Local::load_from_data_dir(dir) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!(error = %e, "failed to load config.json; continuing with defaults");
                algo_config::Local::default()
            }
        },
        None => algo_config::Local::default(),
    }
}

/// Resolve a catchpoint file's output path: the explicit `--output` when
/// given, else `<CatchpointDir>/<default_filename>` when `config.json` sets
/// a non-empty `CatchpointDir` (go: `config.Local.CatchpointDir`, issue
/// #749) — matching go's "falls back to a configured directory" model
/// adapted to algod-rust's simpler one-shot-CLI catchpoint tooling (no
/// implicit hot/cold directory split, see the `catchpoint_dir` field doc
/// in `algo-config`).
fn resolve_catchpoint_output_path(
    output: Option<PathBuf>,
    catchpoint_dir: &str,
    default_filename: &str,
) -> anyhow::Result<PathBuf> {
    match output {
        Some(p) => Ok(p),
        None if !catchpoint_dir.is_empty() => Ok(Path::new(catchpoint_dir).join(default_filename)),
        None => anyhow::bail!(
            "must specify --output, or set a non-empty CatchpointDir in \
             <data-dir>/config.json"
        ),
    }
}

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
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let timer = Instant::now();
    let node_config = load_node_config(data_dir);

    // Step 1: Open database connection. `db_path` is a ledger prefix (or
    // legacy `.sqlite`-suffixed path); the helper opens the tracker file
    // and attaches the block file as `blockdb`, matching the layout used by
    // sync/relay/participate so downstream tooling sees the same data.
    // Import is exactly the "rebuild" scenario go's
    // `AccountsRebuildSynchronousMode` governs (issue #749).
    let conn = open_ledger_connection_with_sync_mode(
        db_path,
        node_config.accounts_rebuild_synchronous_mode,
    )
    .map_err(|e| anyhow::anyhow!("open db: {e}"))?;

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

        // Always clear genesis metadata during catchpoint import.
        // The catchpoint file does not carry genesis info, and reusing
        // existing values from the DB is unsafe — the DB may have been
        // used with a different network (e.g., importing a mainnet
        // catchpoint into a DB that previously held testnet data).
        let genesis_id = "";
        let genesis_hash = [0u8; 32];
        warn!("genesis metadata not set. Use --genesis-id and --genesis-hash flags or configure via genesis file before processing blocks");
        println!("  WARNING: genesis_id and genesis_hash are not set.");
        println!("           Use --genesis-id and --genesis-hash flags or configure via");
        println!("           genesis file before processing blocks.");

        if let Err(e) = algo_ledger::sqlite::initialize_meta_from_catchpoint(
            &conn,
            import_result.round,
            genesis_id,
            &genesis_hash,
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

    // Step 9: Optionally optimize (VACUUM) the freshly-imported accounts
    // database — go's `OptimizeAccountsDatabaseOnStartup` (issue #749).
    // Import is the point in this CLI's lifecycle closest to go's
    // reload-triggered vacuum, since it just bulk-wrote a fresh snapshot.
    if node_config.optimize_accounts_database_on_startup {
        println!("\nOptimizing (VACUUM) accounts database...");
        let vacuum_timer = Instant::now();
        algo_ledger::sqlite::vacuum_connection(&conn)
            .map_err(|e| anyhow::anyhow!("vacuum accounts database: {e}"))?;
        println!(
            "Vacuum complete ({:.1}s)",
            vacuum_timer.elapsed().as_secs_f64()
        );
    }

    let total_elapsed = timer.elapsed();
    println!("=== Done ({:.1}s total) ===", total_elapsed.as_secs_f64());

    Ok(())
}

/// Run the catchpoint verify subcommand (verify an already-imported database).
pub async fn run_verify(
    db_path: &Path,
    file_path: Option<&Path>,
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let node_config = load_node_config(data_dir);
    // Open via the split-ledger helper so the verify pass sees the same data
    // (tracker + attached `blockdb`) that import/sync wrote.
    let conn = open_ledger_connection_with_sync_mode(
        db_path,
        node_config.accounts_rebuild_synchronous_mode,
    )
    .map_err(|e| anyhow::anyhow!("open db: {e}"))?;

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

/// Run the catchpoint export subcommand.
///
/// Writes a go-algorand-format catchpoint file from the local ledger's
/// tracker tables. See `algo_ledger::catchpoint::writer` and
/// `../go-algorand/ledger/catchpointfilewriter.go`.
#[allow(clippy::too_many_arguments)]
pub async fn run_export(
    db_path: &Path,
    output: Option<PathBuf>,
    round: Option<u64>,
    blocks_round: Option<u64>,
    block_digest: Option<&str>,
    no_online_data: bool,
    no_gzip: bool,
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let node_config = load_node_config(data_dir);
    let conn = open_ledger_connection_with_sync_mode(
        db_path,
        node_config.accounts_rebuild_synchronous_mode,
    )
    .map_err(|e| anyhow::anyhow!("open db: {e}"))?;

    // Default the snapshot round to whatever the tracker DB is committed at.
    let balances_round = match round {
        Some(r) => r,
        None => {
            let r: i64 = conn
                .query_row(
                    "SELECT rnd FROM acctrounds WHERE id = 'acctbase'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| {
                    anyhow::anyhow!("could not read acctrounds('acctbase'); pass --round: {e}")
                })?;
            r as u64
        }
    };
    let blocks_round = blocks_round.unwrap_or(balances_round);

    let block_header_digest = match block_digest {
        Some(hex) => parse_hex32(hex)?,
        None => block_header_digest_at(&conn, blocks_round)?,
    };

    let default_filename = format!(
        "{balances_round}.catchpoint{}",
        if no_gzip { ".tar" } else { ".tar.gz" }
    );
    let output =
        resolve_catchpoint_output_path(output, &node_config.catchpoint_dir, &default_filename)?;

    println!("=== Catchpoint Export ===");
    println!("Database:       {}", db_path.display());
    println!("Output:         {}", output.display());
    println!("Balances round: {balances_round}");
    println!("Blocks round:   {blocks_round}");

    let opts = ExportOptions {
        balances_round,
        blocks_round,
        block_header_digest,
        include_online_data: !no_online_data,
        gzip: !no_gzip,
        ..Default::default()
    };

    let timer = Instant::now();
    let result = export_catchpoint_file(&conn, &output, &opts)
        .map_err(|e| anyhow::anyhow!("export failed: {e}"))?;
    let elapsed = timer.elapsed();

    println!("Export complete ({:.1}s)", elapsed.as_secs_f64());
    println!("  Label:               {}", result.label);
    println!("  Accounts:            {}", result.total_accounts);
    println!("  Chunks:              {}", result.total_chunks);
    println!("  KVs:                 {}", result.total_kvs);
    println!("  Online accounts:     {}", result.total_online_accounts);
    println!(
        "  Online round params: {}",
        result.total_online_round_params
    );
    println!("  File size:           {} bytes", result.file_size);
    info!(label = %result.label, size = result.file_size, "catchpoint exported");

    Ok(())
}

/// Parse a 64-character hex string into a 32-byte digest.
fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        anyhow::bail!("block digest must be 64 hex characters, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in block digest: {e}"))?;
    }
    Ok(out)
}

/// Compute the block header digest of `round` from the attached block DB.
fn block_header_digest_at(conn: &rusqlite::Connection, round: u64) -> anyhow::Result<[u8; 32]> {
    let hdrdata: Vec<u8> = conn
        .query_row(
            "SELECT hdrdata FROM blockdb.blocks WHERE rnd = ?1",
            rusqlite::params![round as i64],
            |row| row.get(0),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "block {round} not found in the block DB; pass --block-digest instead: {e}"
            )
        })?;
    let header: algo_types::BlockHeader = rmp_serde::from_slice(&hdrdata)
        .map_err(|e| anyhow::anyhow!("decode block {round} header: {e}"))?;
    Ok(algo_codec::compute_block_header_digest(&header).0)
}

/// Run the catchpoint download subcommand.
pub async fn run_download(
    algod_url: &str,
    algod_token: &str,
    genesis_id: &str,
    round: u64,
    output: Option<PathBuf>,
    data_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let node_config = load_node_config(data_dir);
    let output = resolve_catchpoint_output_path(
        output,
        &node_config.catchpoint_dir,
        &format!("{round}.catchpoint"),
    )?;

    println!("=== Catchpoint Download ===");
    println!("URL:        {algod_url}");
    println!("Genesis ID: {genesis_id}");
    println!("Round:      {round}");
    println!("Output:     {}", output.display());

    // go: MaxCatchpointDownloadDuration (overall request timeout) and
    // MinCatchpointFileDownloadBytesPerSecond (per-chunk stall detection),
    // issue #749 — previously hardcoded to a 30-minute timeout with no
    // stall detection at all.
    let download_config = CatchpointDownloadConfig {
        timeout: std::time::Duration::from_nanos(
            node_config.max_catchpoint_download_duration.max(0) as u64,
        ),
        min_bytes_per_second: node_config.min_catchpoint_file_download_bytes_per_second,
        ..Default::default()
    };
    let downloader = CatchpointDownloader::with_config(algod_url, algod_token, download_config);

    let timer = Instant::now();
    downloader
        .download(
            genesis_id,
            round,
            &output,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_output_path_uses_explicit_output_when_given() {
        let resolved =
            resolve_catchpoint_output_path(Some(PathBuf::from("/tmp/x.tar.gz")), "", "default")
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/x.tar.gz"));
    }

    #[test]
    fn resolve_output_path_explicit_output_wins_over_catchpoint_dir() {
        let resolved = resolve_catchpoint_output_path(
            Some(PathBuf::from("/tmp/x.tar.gz")),
            "/data/catchpoints",
            "default",
        )
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/x.tar.gz"));
    }

    #[test]
    fn resolve_output_path_falls_back_to_catchpoint_dir() {
        let resolved =
            resolve_catchpoint_output_path(None, "/data/catchpoints", "42.catchpoint").unwrap();
        assert_eq!(resolved, PathBuf::from("/data/catchpoints/42.catchpoint"));
    }

    #[test]
    fn resolve_output_path_errors_when_neither_output_nor_catchpoint_dir_is_set() {
        let err = resolve_catchpoint_output_path(None, "", "42.catchpoint").unwrap_err();
        assert!(err.to_string().contains("CatchpointDir"));
    }

    #[test]
    fn load_node_config_with_no_data_dir_returns_go_matching_defaults() {
        let cfg = load_node_config(None);
        assert_eq!(cfg, algo_config::Local::default());
        assert_eq!(cfg.accounts_rebuild_synchronous_mode, 1);
        assert_eq!(cfg.ledger_synchronous_mode, 2);
    }

    #[test]
    fn load_node_config_reads_data_dir_config_json() {
        let dir = std::env::temp_dir().join(format!(
            "algod-rust-catchpoint-cli-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(algo_config::CONFIG_FILENAME),
            r#"{"CatchpointDir": "/data/catchpoints", "AccountsRebuildSynchronousMode": 3}"#,
        )
        .unwrap();

        let cfg = load_node_config(Some(&dir));
        assert_eq!(cfg.catchpoint_dir, "/data/catchpoints");
        assert_eq!(cfg.accounts_rebuild_synchronous_mode, 3);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
