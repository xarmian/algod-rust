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

//! Transaction pool for algod-rust.
//!
//! This crate implements the transaction pool that validates, caches, and
//! prioritises pending transactions for block assembly.  It mirrors the
//! behaviour of go-algorand's `data/pools` package.

pub mod app_rate_limiter;
pub mod broadcast;
pub mod config;
pub mod elastic_rate_limiter;
pub mod error;
pub mod fee;
pub mod pool;
pub mod status_cache;
pub mod traits;

pub use app_rate_limiter::AppRateLimiter;
pub use broadcast::{DrainIterator, NoOpBroadcaster, TransactionBroadcaster};
pub use config::PoolConfig;
pub use elastic_rate_limiter::{
    CapacityGuard, CongestionManager, ElasticRateLimiter, ElasticRateLimiterError,
    RedCongestionManager,
};
pub use error::{PoolError, PoolErrorTag};
pub use pool::TransactionPool;
pub use status_cache::StatusCache;
