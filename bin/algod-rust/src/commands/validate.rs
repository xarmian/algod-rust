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

use std::path::Path;

use algo_conformance::{compare_block, ComparisonStatus, ConformanceReport};
use algo_rest_client::{AlgodClient, BlockSource};
use algo_types::Round;
use chrono::Utc;
use tracing::{error, info};

pub async fn run(
    algod_url: &str,
    algod_token: &str,
    start: u64,
    end: Option<u64>,
    fail_fast: bool,
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

    info!(start, end, fail_fast, "validating blocks");

    // Determine prev_timestamp and genesis info for block validation.
    // For start <= 1, use prev_timestamp = 0 (genesis). Otherwise fetch
    // the block at start-1 to get its timestamp.
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
        // For round 0 or 1, fetch the start block itself to get genesis info.
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

    let started_at = Utc::now().to_rfc3339();
    let mut results = Vec::new();

    let mut round = start;
    while round <= end {
        let raw = client.get_block_raw(Round(round)).await?;
        let result = compare_block(
            &raw,
            Round(round),
            prev_timestamp,
            &genesis_id,
            &genesis_hash,
        );
        info!(
            round,
            status = ?result.status,
            mismatches = result.mismatches.len(),
            duration_ms = result.duration_ms,
        );
        // Only update prev_timestamp when the block decoded successfully (Some).
        // On decode failure block_timestamp is None, preserving the last known
        // good timestamp to avoid cascading false failures.
        if let Some(ts) = result.block_timestamp {
            prev_timestamp = Some(ts);
        }
        let failed = result.status == ComparisonStatus::Fail;
        results.push(result);
        if fail_fast && failed {
            error!(round, "fail-fast: stopping on first failure");
            break;
        }
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
