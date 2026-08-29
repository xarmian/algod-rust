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

//! Shared types used across request and response shapes.
//!
//! Ported from `daemon/kmd/lib/kmdapi/common.go`.

use serde::{Deserialize, Serialize};

use crate::base64_bytes;

/// Master derivation key — 32 bytes, base64-encoded on the wire.
/// Mirrors `APIV1MasterDerivationKey = crypto.MasterDerivationKey`
/// (common.go:30, `crypto/curve25519.go:106` — `[masterDerivationKeyLenBytes]byte`).
pub type APIV1MasterDerivationKey = [u8; 32];

/// Public key — 32 bytes, base64-encoded on the wire. Mirrors
/// `APIV1PublicKey = crypto.PublicKey` (common.go:38).
pub type APIV1PublicKey = [u8; 32];

/// Private key — 64 bytes (Ed25519 expanded `seed || pubkey`),
/// base64-encoded on the wire. Mirrors `APIV1PrivateKey =
/// crypto.PrivateKey` (common.go:34, `ed25519PrivateKey [64]byte`).
pub type APIV1PrivateKey = [u8; 64];

/// Common envelope embedded in every v1 response. Mirrors
/// `APIV1ResponseEnvelope` (responses.go:29).
///
/// `error` defaults to `false` and `message` to `""`; both are
/// `skip_serializing_if` so the success path emits an empty object,
/// matching go-codec's `_struct codec:",omitempty,omitemptyarray"`
/// directive on the Go struct.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1ResponseEnvelope {
    #[serde(default, skip_serializing_if = "is_false", rename = "error")]
    pub error: bool,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "message")]
    pub message: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The API's representation of a wallet. Mirrors `APIV1Wallet`
/// (common.go:41).
///
/// `APIV1Wallet` lacks the `_struct codec:",omitempty"` directive in
/// Go, so go-codec includes every field — even zero-valued ones. We
/// mirror that by NOT using `skip_serializing_if` here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1Wallet {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "driver_name")]
    pub driver_name: String,
    #[serde(rename = "driver_version")]
    pub driver_version: u32,
    #[serde(rename = "mnemonic_ux")]
    pub supports_mnemonic_ux: bool,
    /// Mirrors `[]protocol.TxType` — list of transaction-type strings
    /// (`"pay"`, `"keyreg"`, etc.). Modeled as `Vec<String>` to avoid
    /// pulling in `algo-types` for an opaque tag.
    #[serde(rename = "supported_txs", default)]
    pub supported_transactions: Vec<String>,
}

/// Wallet handle + remaining lifetime, returned by `/wallet/info` and
/// `/wallet/renew`. Mirrors `APIV1WalletHandle` (common.go:52).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1WalletHandle {
    #[serde(rename = "wallet")]
    pub wallet: APIV1Wallet,
    #[serde(rename = "expires_seconds")]
    pub expires_seconds: i64,
}

// ---- Multisig wire shapes --------------------------------------------------
//
// Mirrors `crypto.MultisigSig` / `crypto.MultisigSubsig` (Go: `crypto/multisig.go`),
// duplicated here so this crate doesn't depend on `algo-types`. The kmd REST
// surface accepts and returns multisigs in this shape on the wire.
// Field tags match go-codec's `json:"..."` plus omitempty behavior.

/// One subsig within a multisig — a public key plus its signature
/// (zeroed when unsigned). Mirrors `crypto.MultisigSubsig`
/// (`crypto/multisig.go`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSubsig {
    /// 32-byte Ed25519 public key, base64-encoded on the wire.
    #[serde(rename = "pk", with = "base64_bytes::array_32")]
    pub public_key: [u8; 32],

    /// 64-byte Ed25519 signature (zeroed if this subsig hasn't been
    /// signed yet), base64-encoded on the wire. Omitted when all-zero.
    #[serde(
        rename = "s",
        default = "zero_sig",
        skip_serializing_if = "is_zero_sig",
        with = "base64_bytes::array_64"
    )]
    pub signature: [u8; 64],
}

fn zero_sig() -> [u8; 64] {
    [0u8; 64]
}

fn is_zero_sig(s: &[u8; 64]) -> bool {
    s.iter().all(|&b| b == 0)
}

/// A multisig signature payload — version + threshold + the list of
/// subsigs (one per signer in the preimage). Mirrors `crypto.MultisigSig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSig {
    #[serde(rename = "v", default, skip_serializing_if = "is_zero_u8")]
    pub version: u8,

    #[serde(rename = "thr", default, skip_serializing_if = "is_zero_u8")]
    pub threshold: u8,

    /// `subsigs[i]` is the subsig at position `i` in the preimage's
    /// public-key list (order is significant).
    #[serde(rename = "subsig", default, skip_serializing_if = "Vec::is_empty")]
    pub subsigs: Vec<MultisigSubsig>,
}

fn is_zero_u8(n: &u8) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_omits_default_fields() {
        let env = APIV1ResponseEnvelope::default();
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn envelope_includes_set_fields() {
        let env = APIV1ResponseEnvelope {
            error: true,
            message: "wrong password".into(),
        };
        let json: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(json["error"], true);
        assert_eq!(json["message"], "wrong password");
    }

    #[test]
    fn wallet_includes_all_fields_even_when_zero() {
        // APIV1Wallet has no omitempty in Go, so every field must
        // appear on the wire — including defaults.
        let w = APIV1Wallet::default();
        let json: serde_json::Value = serde_json::to_value(&w).unwrap();
        for key in [
            "id",
            "name",
            "driver_name",
            "driver_version",
            "mnemonic_ux",
            "supported_txs",
        ] {
            assert!(
                json.get(key).is_some(),
                "field {key} must be present in default APIV1Wallet JSON"
            );
        }
    }
}
