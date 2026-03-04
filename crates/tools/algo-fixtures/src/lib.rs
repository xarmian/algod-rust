use std::path::{Path, PathBuf};

use algo_error::Result;
use algo_rest_client::BlockSource;
use algo_types::Round;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Metadata about a captured block fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureMetadata {
    pub round: u64,
    pub captured_at: String,
    pub source_url: String,
}

/// Capture a single block fixture to disk.
///
/// Writes three files:
/// - `block_{round}.msgpack` — raw bytes from the REST API
/// - `block_{round}.json` — decoded block as JSON (for debugging)
/// - `block_{round}.meta.json` — capture metadata
pub async fn capture_block(
    source: &dyn BlockSource,
    round: Round,
    dir: &Path,
    source_url: &str,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(dir).await?;

    let raw = source.get_block_raw(round).await?;
    let block_resp = algo_codec::decode_block_response(&raw)?;

    let base = dir.join(format!("block_{}", round));

    // Write raw msgpack
    let msgpack_path = base.with_extension("msgpack");
    tokio::fs::write(&msgpack_path, &raw).await?;

    // Write decoded JSON for debugging
    let json_path = base.with_extension("json");
    let json = serde_json::to_string_pretty(&block_resp.block).map_err(|e| {
        algo_error::AlgoError::Codec {
            source: Box::new(e),
            context: format!("serializing block {round} to JSON"),
        }
    })?;
    tokio::fs::write(&json_path, json).await?;

    // Write metadata
    let meta = FixtureMetadata {
        round: round.0,
        captured_at: Utc::now().to_rfc3339(),
        source_url: source_url.to_string(),
    };
    let meta_path = base.with_extension("meta.json");
    let meta_json =
        serde_json::to_string_pretty(&meta).map_err(|e| algo_error::AlgoError::Codec {
            source: Box::new(e),
            context: "serializing fixture metadata".into(),
        })?;
    tokio::fs::write(&meta_path, meta_json).await?;

    info!(round = %round, path = %msgpack_path.display(), "captured block fixture");
    Ok(msgpack_path)
}

/// Capture a range of block fixtures.
///
/// If a block is not found (404), capture stops and returns the blocks
/// captured so far. This is expected in DEV_MODE where the chain may
/// not have reached the requested end round yet.
pub async fn capture_range(
    source: &dyn BlockSource,
    start: Round,
    end: Round,
    dir: &Path,
    source_url: &str,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let mut round = start;
    while round <= end {
        match capture_block(source, round, dir, source_url).await {
            Ok(path) => paths.push(path),
            Err(algo_error::AlgoError::NotFound(_)) => {
                info!(
                    round = %round,
                    captured = paths.len(),
                    "block not found, treating as end of chain"
                );
                break;
            }
            Err(e) => return Err(e),
        }
        round = round.next();
    }
    Ok(paths)
}

/// Load a raw fixture from disk.
pub fn load_fixture_sync(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(Into::into)
}

/// Load fixture metadata from disk.
pub fn load_metadata_sync(path: &Path) -> Result<FixtureMetadata> {
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data).map_err(|e| algo_error::AlgoError::Codec {
        source: Box::new(e),
        context: format!("parsing fixture metadata from {}", path.display()),
    })
}
