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
