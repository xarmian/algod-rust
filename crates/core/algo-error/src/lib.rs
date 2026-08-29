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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AlgoError {
    #[error("codec error: {context}")]
    Codec {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("REST client error: {context}")]
    RestClient {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: String,
    },

    #[error("conformance error: {message}")]
    Conformance { message: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("validation error: {message}")]
    Validation { message: String },

    #[error("ledger error: {message}")]
    Ledger { message: String },

    #[error("AVM: {message}")]
    Avm { message: String },

    #[error("network error: {message}")]
    Network { message: String },
}

pub type Result<T> = std::result::Result<T, AlgoError>;
