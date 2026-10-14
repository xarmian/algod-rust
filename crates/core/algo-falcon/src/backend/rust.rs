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

//! The pure-Rust backend adapter.
//!
//! DIVERGENCE DIV-001: go-algorand calls the C library through cgo; algod-rust
//! implements deterministic Falcon-1024 in Rust (`crate::rs`, landing module by
//! module in Phase 21, epic #1926) and keeps the C library as a selectable
//! backend. See `docs/DIVERGENCES.md`.
//!
//! Until the port lands (verify: #1935, sign: #1936, keygen: #1937) every
//! entry point reports [`FalconError::BackendUnavailable`], so selecting the
//! Rust backend fails loudly instead of silently falling back to C.

use crate::{FalconBackend, FalconError, FALCON_DET1024_SIG_CT_SIZE};

fn unavailable<T>() -> Result<T, FalconError> {
    Err(FalconError::BackendUnavailable(FalconBackend::Rust))
}

pub(crate) fn verify(_pubkey: &[u8], _sig: &[u8], _data: &[u8]) -> Result<bool, FalconError> {
    unavailable()
}

pub(crate) fn keygen(_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FalconError> {
    unavailable()
}

pub(crate) fn sign(_privkey: &[u8], _data: &[u8]) -> Result<Vec<u8>, FalconError> {
    unavailable()
}

pub(crate) fn convert_compressed_to_ct(
    _sig_compressed: &[u8],
) -> Result<[u8; FALCON_DET1024_SIG_CT_SIZE], FalconError> {
    unavailable()
}

pub(crate) fn salt_version(_sig: &[u8]) -> Result<u8, FalconError> {
    unavailable()
}
