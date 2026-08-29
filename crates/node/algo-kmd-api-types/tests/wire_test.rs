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

//! Cross-implementation wire-shape tests.
//!
//! Parses each section of `tests/fixtures/go_wire_samples.txt` (a
//! snapshot of go-algorand's kmd v1 JSON output captured by
//! `tools/kmd-api-wire-capture`) into the corresponding Rust type and
//! asserts a semantic round-trip:
//!
//! 1. Go-emitted bytes → Rust struct via `serde_json::from_str`
//! 2. Rust struct → JSON via `serde_json::to_value`
//! 3. Go-emitted bytes → `serde_json::Value`
//! 4. Step-2 Value equals Step-3 Value (deep equality, ignores
//!    map-key ordering + whitespace)
//!
//! Byte-for-byte parity is the server response writer's job (TASK-213)
//! — it'll re-serialize with canonical sort + 2-space indent. Here we
//! just prove the shapes match.

use algo_kmd_api_types::responses::{
    APIV1GETWalletsResponse, APIV1POSTKeyExportResponse, APIV1POSTMasterKeyExportResponse,
    APIV1POSTMultisigExportResponse, APIV1POSTWalletInitResponse, VersionsResponse,
};

const FIXTURE: &str = include_str!("fixtures/go_wire_samples.txt");

/// Pull the section starting with `# <name>` and continuing until the
/// next `# ` header or EOF.
fn section(name: &str) -> &'static str {
    let header = format!("# {name}\n");
    let start = FIXTURE
        .find(&header)
        .unwrap_or_else(|| panic!("section {name} not in fixture"))
        + header.len();
    let rest = &FIXTURE[start..];
    let end = rest.find("\n# ").map(|i| i + 1).unwrap_or(rest.len());
    rest[..end].trim_end_matches('\n')
}

fn assert_round_trip<T>(name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let go_bytes = section(name);
    let rust: T =
        serde_json::from_str(go_bytes).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"));
    let rust_value =
        serde_json::to_value(&rust).unwrap_or_else(|e| panic!("{name}: serialize failed: {e}"));
    let go_value: serde_json::Value = serde_json::from_str(go_bytes)
        .unwrap_or_else(|e| panic!("{name}: go-value parse failed: {e}"));
    assert_eq!(
        rust_value, go_value,
        "{name}: Rust round-trip diverges from Go bytes"
    );
}

#[test]
fn masterkey_export_response_matches_go() {
    assert_round_trip::<APIV1POSTMasterKeyExportResponse>("masterkey-export-response");
}

#[test]
fn list_wallets_response_matches_go() {
    assert_round_trip::<APIV1GETWalletsResponse>("list-wallets-response");
}

#[test]
fn init_wallet_error_response_matches_go() {
    assert_round_trip::<APIV1POSTWalletInitResponse>("init-wallet-error-response");
}

#[test]
fn key_export_response_matches_go() {
    assert_round_trip::<APIV1POSTKeyExportResponse>("key-export-response");
}

#[test]
fn multisig_export_response_matches_go() {
    assert_round_trip::<APIV1POSTMultisigExportResponse>("multisig-export-response");
}

#[test]
fn versions_response_matches_go() {
    assert_round_trip::<VersionsResponse>("versions-response");
}

#[test]
fn masterkey_value_decodes_to_expected_bytes() {
    // Spot-check that the base64 string in the Go fixture actually
    // decodes into the bytes 0x01..0x20 we put in.
    let r: APIV1POSTMasterKeyExportResponse =
        serde_json::from_str(section("masterkey-export-response")).unwrap();
    let expected: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    assert_eq!(r.master_derivation_key, expected);
}

#[test]
fn init_error_response_envelope_is_decoded() {
    let r: APIV1POSTWalletInitResponse =
        serde_json::from_str(section("init-wallet-error-response")).unwrap();
    assert!(r.envelope.error);
    assert_eq!(r.envelope.message, "wrong password");
    assert_eq!(r.wallet_handle_token, "");
}
