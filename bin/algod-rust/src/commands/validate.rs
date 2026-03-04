use std::path::Path;

use algo_conformance::{compare_block, ConformanceReport};
use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::Round;
use chrono::Utc;
use tracing::info;

pub async fn run(
    algod_url: &str,
    algod_token: &str,
    start: u64,
    end: Option<u64>,
    report_path: Option<&Path>,
) -> anyhow::Result<()> {
    let client = AlgodClient::new(algod_url, algod_token);

    let end = match end {
        Some(e) => e,
        None => {
            let status = client.get_status().await?;
            status.last_round
        }
    };

    info!(start, end, "validating blocks");

    let started_at = Utc::now().to_rfc3339();
    let mut results = Vec::new();

    let mut round = start;
    while round <= end {
        let raw = client.get_block_raw(Round(round)).await?;
        let result = compare_block(&raw, Round(round));
        info!(
            round,
            status = ?result.status,
            mismatches = result.mismatches.len(),
            duration_ms = result.duration_ms,
        );
        results.push(result);
        round += 1;
    }

    let finished_at = Utc::now().to_rfc3339();
    let report = ConformanceReport::new(results, started_at, finished_at);

    algo_conformance::print_summary(&report);

    if let Some(path) = report_path {
        algo_conformance::write_report(&report, path)?;
        info!(path = %path.display(), "report written");
    }

    if report.failed > 0 {
        anyhow::bail!("{} rounds failed conformance", report.failed);
    }

    Ok(())
}
