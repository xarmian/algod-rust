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

mod catchpoint_download;
mod client;
pub mod gossip_block_source;
pub mod http_block_fetcher;
mod parallel_fetch;
pub mod ranked_catchpoint_source;
mod traits;
mod types;

pub use catchpoint_download::{CatchpointDownloadConfig, CatchpointDownloader, DownloadProgress};
pub use client::{AlgodClient, ClientConfig};
pub use gossip_block_source::{decode_block_cert, GossipBlockSource, GossipBlockSourceConfig};
pub use http_block_fetcher::{HttpBlockFetchError, HttpBlockFetcher, BLOCK_RESPONSE_CONTENT_TYPE};
pub use parallel_fetch::{ParallelBlockFetcher, DEFAULT_CONCURRENCY};
pub use ranked_catchpoint_source::RankedCatchpointSource;
pub use traits::BlockSource;
pub use types::{
    AccountInfo, AccountParticipation, AlgodVersions, NodeStatus, ParticipationKey,
    ParticipationKeyAdded, PendingTxnInfo, PostTransactionResponse, SuggestedParams,
    TealCompileResult, TxId,
};
