use std::path::Path;

use algo_rest_client::AlgodClient;
use algo_types::Round;
use tracing::info;

pub async fn run(
    algod_url: &str,
    algod_token: &str,
    start: u64,
    end: u64,
    out: &Path,
) -> anyhow::Result<()> {
    let client = AlgodClient::new(algod_url, algod_token);

    info!(start, end, out = %out.display(), "capturing block fixtures");

    let paths =
        algo_fixtures::capture_range(&client, Round(start), Round(end), out, algod_url).await?;

    info!(count = paths.len(), "capture complete");
    Ok(())
}
