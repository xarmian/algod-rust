use std::path::PathBuf;
use std::sync::Arc;

use algo_codec::{canonical_encode_block_header_from_block, decode_block_response, encode_block};
use algo_error::AlgoError;
use algo_ledger::sync::{SyncBackend, SyncConfig, SyncOrchestrator};
use algo_rest_client::{AlgodClient, BlockSource, CatchpointDownloader, ParallelBlockFetcher};
use algo_types::{Block, Round};
use tokio_util::sync::CancellationToken;
use tracing::info;

// ---------------------------------------------------------------------------
// AlgodSyncBackend — real SyncBackend using AlgodClient
// ---------------------------------------------------------------------------

/// A real [`SyncBackend`] implementation backed by [`AlgodClient`] and
/// [`CatchpointDownloader`].
///
/// This bridges the gap between `algo-ledger` (which cannot depend on
/// `algo-rest-client`) and the actual network operations needed for sync.
struct AlgodSyncBackend {
    client: AlgodClient,
    downloader: CatchpointDownloader,
    /// Tokio runtime handle for running async operations from sync context.
    rt: tokio::runtime::Handle,
    /// Stored URL for constructing parallel fetchers.
    algod_url: String,
    /// Stored token for constructing parallel fetchers.
    algod_token: String,
}

impl AlgodSyncBackend {
    fn new(algod_url: &str, algod_token: &str) -> Self {
        let client = AlgodClient::new(algod_url, algod_token);
        let downloader = CatchpointDownloader::new(algod_url, algod_token);
        let rt = tokio::runtime::Handle::current();
        Self {
            client,
            downloader,
            rt,
            algod_url: algod_url.to_string(),
            algod_token: algod_token.to_string(),
        }
    }
}

impl SyncBackend for AlgodSyncBackend {
    fn is_noop(&self) -> bool {
        false
    }

    fn download_catchpoint(
        &self,
        genesis_id: &str,
        round: u64,
        dest_path: &std::path::Path,
    ) -> Result<(), AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                self.downloader
                    .download::<fn(algo_rest_client::DownloadProgress)>(
                        genesis_id, round, dest_path, None,
                    )
                    .await
            })
        })
    }

    fn fetch_block_raw(&self, round: u64) -> Result<(String, Vec<u8>, Vec<u8>), AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let raw = self.client.get_block_raw(Round(round)).await?;
                let br = decode_block_response(&raw)?;
                let proto = br.block.current_protocol.clone();
                // Encode in the same format that apply_block uses:
                // hdrdata = canonical block header encoding (for heartbeat
                //           validation and block digest computation)
                // blkdata = full block msgpack encoding (for block replay)
                let hdrdata = canonical_encode_block_header_from_block(&br.block);
                let blkdata = encode_block(&br.block)?;
                Ok((proto, hdrdata, blkdata))
            })
        })
    }

    fn fetch_block(&self, round: u64) -> Result<Block, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let raw = self.client.get_block_raw(Round(round)).await?;
                let br = decode_block_response(&raw)?;
                Ok(br.block)
            })
        })
    }

    fn get_current_round(&self) -> Result<u64, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let status = self.client.get_status().await?;
                Ok(status.last_round)
            })
        })
    }

    fn discover_catchpoint(&self) -> Result<Option<String>, AlgoError> {
        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let status = self.client.get_status().await?;
                Ok(status.last_catchpoint)
            })
        })
    }

    fn fetch_blocks_batch(
        &self,
        start: u64,
        end: u64,
        concurrency: usize,
    ) -> Result<Vec<(u64, Block)>, AlgoError> {
        if start > end {
            return Ok(Vec::new());
        }

        tokio::task::block_in_place(|| {
            self.rt.block_on(async {
                let source: Arc<dyn BlockSource> =
                    Arc::new(AlgodClient::new(&self.algod_url, &self.algod_token));
                let fetcher = ParallelBlockFetcher::new(source, concurrency);
                let cancel = CancellationToken::new();
                // fetch_range uses half-open [start, end), so add 1 to include `end`.
                let mut rx = fetcher.fetch_range(Round(start), Round(end + 1), cancel);

                let mut blocks = Vec::with_capacity((end - start + 1) as usize);
                while let Some((round, block_resp)) = rx.recv().await {
                    blocks.push((round.0, block_resp.block));
                }

                if blocks.len() != (end - start + 1) as usize {
                    return Err(AlgoError::Ledger {
                        message: format!(
                            "parallel fetch incomplete: expected {} blocks, got {}",
                            end - start + 1,
                            blocks.len()
                        ),
                    });
                }

                Ok(blocks)
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Genesis info resolution
// ---------------------------------------------------------------------------

/// Known genesis IDs for well-known networks.
fn genesis_id_for_network(network: &str) -> Option<&'static str> {
    match network {
        "mainnet" => Some("mainnet-v1.0"),
        "testnet" => Some("testnet-v1.0"),
        _ => None,
    }
}

/// Resolve genesis_id and genesis_hash by fetching block info from the node.
///
/// If `network` is a known preset ("mainnet", "testnet"), the genesis_id is
/// set directly. The genesis_hash is always fetched from the node (by
/// requesting a recent block and reading its header).
async fn resolve_genesis_info(
    client: &AlgodClient,
    network: &str,
) -> anyhow::Result<(String, [u8; 32])> {
    // If the network has a known genesis_id, use it.
    // Either way, we need the genesis_hash from the node.
    let status = client.get_status().await?;
    let round = status.last_round;

    // Fetch a recent block to extract genesis info.
    let raw = client.get_block_raw(Round(round)).await?;
    let br = decode_block_response(&raw)?;

    let genesis_id = if let Some(known_id) = genesis_id_for_network(network) {
        known_id.to_string()
    } else {
        let id = br.block.genesis_id.clone();
        if id.is_empty() {
            anyhow::bail!(
                "could not determine genesis_id: block {round} has no genesis_id and \
                 --network is '{network}' (not a known preset)"
            );
        }
        id
    };

    let genesis_hash: [u8; 32] = br
        .block
        .genesis_hash
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("genesis_hash from block {round} is not 32 bytes"))?;

    info!(
        genesis_id = %genesis_id,
        genesis_hash = hex::encode(genesis_hash),
        source_round = round,
        "resolved genesis info from node"
    );

    Ok((genesis_id, genesis_hash))
}

// Inline hex encoding since we may not have the `hex` crate.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the catchpoint sync path: build a SyncConfig from CLI args, construct
/// a SyncOrchestrator, and drive it through all phases.
///
/// Sets up a progress callback for phase-transition logging and a Ctrl+C
/// handler for graceful shutdown with checkpoint persistence.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    network: &str,
    algod_url: &str,
    algod_token: &str,
    db_path: &std::path::Path,
    catchpoint_label: Option<&str>,
    catchpoint_auto: bool,
    concurrency: usize,
    follow: bool,
    compare: bool,
    trie_path: Option<&std::path::Path>,
    avm_execute: bool,
    fail_fast: bool,
    end: Option<u64>,
) -> anyhow::Result<()> {
    // Determine the catchpoint label to use.
    let label = match (catchpoint_label, catchpoint_auto) {
        (Some(label), _) => {
            info!(catchpoint = label, "using explicit catchpoint label");
            Some(label.to_string())
        }
        (None, true) => {
            info!("auto-discovery mode: orchestrator will discover latest catchpoint");
            None
        }
        (None, false) => {
            // This shouldn't happen — main.rs guards against it — but be safe.
            anyhow::bail!(
                "catchpoint sync requires either --catchpoint <LABEL> or --catchpoint-auto"
            );
        }
    };

    // Resolve genesis info from network preset / node.
    let client = AlgodClient::new(algod_url, algod_token);
    let (genesis_id, genesis_hash) = resolve_genesis_info(&client, network).await?;

    let config = SyncConfig {
        catchpoint_label: label,
        algod_url: algod_url.to_string(),
        algod_token: algod_token.to_string(),
        genesis_id,
        genesis_hash,
        db_path: db_path.to_path_buf(),
        concurrency,
        follow_after_sync: follow,
        compare_mode: compare,
        trie_path: trie_path.map(PathBuf::from),
        avm_execute,
        fail_fast,
        end_round: end,
    };

    info!(
        catchpoint = ?config.catchpoint_label,
        genesis_id = %config.genesis_id,
        algod_url,
        concurrency,
        follow,
        compare,
        avm_execute,
        fail_fast,
        db = %db_path.display(),
        "starting catchpoint sync"
    );

    // Set up cancellation token and Ctrl+C handler.
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Ctrl+C received — shutting down gracefully, saving checkpoint...");
        cancel_clone.cancel();
    });

    // Create the real backend and orchestrator.
    let backend = AlgodSyncBackend::new(algod_url, algod_token);
    let mut orchestrator = SyncOrchestrator::with_backend(config, backend);
    orchestrator.set_cancel(cancel);
    orchestrator.set_progress_callback(Box::new(|progress| {
        let pct = (progress.phase_progress * 100.0) as u32;
        let eta_str = match progress.eta {
            Some(eta) => format!(", ETA {:.0}s", eta.as_secs_f64()),
            None => String::new(),
        };
        info!(
            phase = %progress.state,
            progress_pct = pct,
            elapsed_secs = format!("{:.1}", progress.elapsed.as_secs_f64()),
            "{}{}",
            progress.phase_detail,
            eta_str,
        );
    }));

    let result = orchestrator.run().await?;

    info!(
        final_round = result.final_round,
        accounts_imported = result.accounts_imported,
        blocks_replayed = result.blocks_replayed,
        duration = ?result.duration,
        "catchpoint sync completed"
    );

    println!("=== Catchpoint Sync Summary ===");
    println!("Final round:        {}", result.final_round);
    println!("Accounts imported:  {}", result.accounts_imported);
    println!("Blocks replayed:    {}", result.blocks_replayed);
    println!("Duration:           {:.1}s", result.duration.as_secs_f64());

    Ok(())
}
