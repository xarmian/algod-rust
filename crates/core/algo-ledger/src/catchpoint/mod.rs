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

pub mod checkpoint;
pub mod importer;
pub mod msgp_compat;
pub mod parser;
pub mod state_keys;
pub mod types;
pub mod verify;
pub mod writer;

pub use importer::{import_catchpoint_file, ImportResult, ImportStats};
pub use parser::{CatchpointEntry, CatchpointReader, CatchpointReaderFile};
pub use types::{
    AccountTotals, AlgoCount, BalanceRecordV6, CatchpointBaseAccountData,
    CatchpointBaseOnlineAccountData, CatchpointError, CatchpointFileHeader, CatchpointLabel,
    CatchpointOnlineRoundParamsData, CatchpointResourcesData, CatchpointSnapshotChunkV6,
    KVRecordV6, OnlineAccountRecordV6, OnlineRoundParamsRecordV6, CATCHPOINT_FILE_VERSION_V5,
    CATCHPOINT_FILE_VERSION_V6, CATCHPOINT_FILE_VERSION_V7, CATCHPOINT_FILE_VERSION_V8,
};
pub use verify::{
    build_sp_verification_blob, download_lookback_blocks, hash_sp_verification_blob,
    parse_catchpoint_label, reconstruct_lease_table, validate_post_import, verify_catchpoint,
    CatchpointVerifyResult, ValidationWarning, MAX_TXN_LIFE,
};
pub use writer::{
    export_catchpoint_file, select_catchpoint_file_version, ExportOptions, ExportResult,
    BALANCES_PER_CATCHPOINT_FILE_CHUNK, RESOURCES_PER_CATCHPOINT_FILE_CHUNK,
};
