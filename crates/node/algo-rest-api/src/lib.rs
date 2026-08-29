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

//! Algorand REST API server crate.
//!
//! Provides the HTTP REST API that mirrors go-algorand's `algod` API surface,
//! including `/versions`, `/v2/status`, `/v2/transactions/params`, and more.

pub mod abi;
pub mod auth;
pub mod block_json;
pub mod box_name;
pub mod cors;
pub mod error;
pub mod error_envelope;
pub mod format;
pub mod handlers;
pub mod models;
pub mod node;
pub mod router;
pub mod server;
pub mod source_header;

// Re-export key types for convenience.
pub use error::ErrorResponse;
pub use format::ResponseFormat;
pub use node::{BuildVersion, NodeError, NodeInterface, NodeStatus, ProtocolSwitchInfo};
pub use router::TokenConfig;
pub use server::{ApiServer, ApiServerConfig};
