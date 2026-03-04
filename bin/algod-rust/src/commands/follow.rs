use std::path::Path;

use algo_conformance::{compare_block, ConformanceReport};
use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::Round;
use chrono::Utc;
use tracing::{error, info};

pub async fn run(
    algod_url: &str,
    algod_token: &str,
    report_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let client = AlgodClient::new(algod_url, algod_token);

    if let Some(dir) = report_dir {
        std::fs::create_dir_all(dir)?;
    }

    let status = client.get_status().await?;
    let mut current_round = Round(status.last_round);
    let mut results = Vec::new();
    let started_at = Utc::now().to_rfc3339();

    info!(round = %current_round, "starting follow mode");

    loop {
        // Wait for the next round
        let status = client.wait_for_round(current_round).await?;
        let target = Round(status.last_round);

        // Process all rounds we may have missed
        while current_round < target {
            current_round = current_round.next();

            match client.get_block_raw(current_round).await {
                Ok(raw) => {
                    let result = compare_block(&raw, current_round);
                    info!(
                        round = %current_round,
                        status = ?result.status,
                        mismatches = result.mismatches.len(),
                        txns = ?algo_codec::decode_block_response(&raw)
                            .map(|br| br.block.payset.len())
                            .unwrap_or(0),
                        duration_ms = result.duration_ms,
                    );
                    results.push(result);
                }
                Err(e) => {
                    error!(round = %current_round, error = %e, "failed to fetch block");
                }
            }
        }

        // Write periodic reports every 100 rounds
        if let Some(dir) = report_dir {
            if results.len() >= 100 {
                let finished_at = Utc::now().to_rfc3339();
                let report = ConformanceReport::new(
                    std::mem::take(&mut results),
                    started_at.clone(),
                    finished_at,
                );
                let path = dir.join(format!("conformance-{}.json", current_round));
                algo_conformance::write_report(&report, &path)?;
                info!(path = %path.display(), rounds = report.total_rounds, "periodic report written");
            }
        }
    }
}
