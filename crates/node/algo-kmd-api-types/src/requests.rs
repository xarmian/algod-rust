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

//! v1 request body shapes. Ported from
//! `daemon/kmd/lib/kmdapi/requests.go`.
//!
//! Field names match Go's `json:"..."` tags exactly. Defaults follow
//! serde's standard behavior; on the server side missing fields parse
//! as their type's zero value (matches Go's `json.Unmarshal`).

use serde::{Deserialize, Serialize};

use crate::base64_bytes;
use crate::common::{APIV1MasterDerivationKey, APIV1PrivateKey, APIV1PublicKey, MultisigSig};

// ---- /versions ------------------------------------------------------------

/// Request for `GET /versions`. Empty body. Mirrors `VersionsRequest`
/// (requests.go:31).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionsRequest {}

// ---- Wallet routes --------------------------------------------------------

/// Request for `GET /v1/wallets`. Empty body. Mirrors
/// `APIV1GETWalletsRequest` (requests.go:38).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1GETWalletsRequest {}

/// `POST /v1/wallet`. Mirrors `APIV1POSTWalletRequest` (requests.go:45).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletRequest {
    #[serde(rename = "wallet_name", default)]
    pub wallet_name: String,
    #[serde(rename = "wallet_driver_name", default)]
    pub wallet_driver_name: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
    /// 32-byte MDK, base64 on the wire. All-zero means "generate a
    /// fresh one" (matches Go's check at sqlite.go:451).
    #[serde(
        rename = "master_derivation_key",
        default = "zero_mdk",
        with = "base64_bytes::array_32"
    )]
    pub master_derivation_key: APIV1MasterDerivationKey,
}

fn zero_mdk() -> APIV1MasterDerivationKey {
    [0u8; 32]
}

/// `POST /v1/wallet/init`. Mirrors `APIV1POSTWalletInitRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletInitRequest {
    #[serde(rename = "wallet_id", default)]
    pub wallet_id: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

/// `POST /v1/wallet/release`. Mirrors `APIV1POSTWalletReleaseRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletReleaseRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
}

/// `POST /v1/wallet/renew`. Mirrors `APIV1POSTWalletRenewRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletRenewRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
}

/// `POST /v1/wallet/rename`. Mirrors `APIV1POSTWalletRenameRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletRenameRequest {
    #[serde(rename = "wallet_id", default)]
    pub wallet_id: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
    /// Go's JSON tag is `wallet_name` (sic — same key as create).
    #[serde(rename = "wallet_name", default)]
    pub new_wallet_name: String,
}

/// `POST /v1/wallet/info`. Mirrors `APIV1POSTWalletInfoRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletInfoRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
}

/// `POST /v1/master-key/export`. Mirrors
/// `APIV1POSTMasterKeyExportRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMasterKeyExportRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

// ---- Key routes -----------------------------------------------------------

/// `POST /v1/key/import`. Mirrors `APIV1POSTKeyImportRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyImportRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    /// 64-byte Ed25519 expanded private key, base64.
    #[serde(
        rename = "private_key",
        default = "zero_sk",
        with = "base64_bytes::array_64"
    )]
    pub private_key: APIV1PrivateKey,
}

fn zero_sk() -> APIV1PrivateKey {
    [0u8; 64]
}

impl Default for APIV1POSTKeyImportRequest {
    fn default() -> Self {
        Self {
            wallet_handle_token: String::new(),
            private_key: [0u8; 64],
        }
    }
}

/// `POST /v1/key/export`. Mirrors `APIV1POSTKeyExportRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyExportRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    /// Base32-with-checksum Algorand address string. The handler
    /// decodes to the underlying 32-byte public key.
    #[serde(rename = "address", default)]
    pub address: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

/// `POST /v1/key` — generate a new key. Mirrors `APIV1POSTKeyRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    /// SQLite driver always rejects this with `errNoMnemonicUX`
    /// (sqlite.go:850), but the field is accepted for API parity.
    #[serde(rename = "display_mnemonic", default)]
    pub display_mnemonic: bool,
}

/// `DELETE /v1/key`. Mirrors `APIV1DELETEKeyRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1DELETEKeyRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "address", default)]
    pub address: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

/// `POST /v1/key/list`. Mirrors `APIV1POSTKeyListRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyListRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
}

// ---- Sign routes ----------------------------------------------------------

/// `POST /v1/transaction/sign`. Mirrors
/// `APIV1POSTTransactionSignRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTTransactionSignRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,

    /// Base64-msgpack-encoded `Transaction` (or the `txn` field of a
    /// `SignedTxn` that the SDK is asking us to re-sign).
    #[serde(rename = "transaction", default, with = "base64_bytes::vec")]
    pub transaction: Vec<u8>,

    /// Public key to sign with — 32-byte address, base64. All-zero
    /// means "infer from txn" (mirrors Go's sqlite.go behavior at the
    /// SignTransaction call site).
    #[serde(
        rename = "public_key",
        default = "zero_pk",
        with = "base64_bytes::array_32"
    )]
    pub public_key: APIV1PublicKey,

    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

fn zero_pk() -> APIV1PublicKey {
    [0u8; 32]
}

impl Default for APIV1POSTTransactionSignRequest {
    fn default() -> Self {
        Self {
            wallet_handle_token: String::new(),
            transaction: Vec::new(),
            public_key: zero_pk(),
            wallet_password: String::new(),
        }
    }
}

/// `POST /v1/program/sign`. Mirrors `APIV1POSTProgramSignRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTProgramSignRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "address", default)]
    pub address: String,
    /// Note: Go's JSON tag is `data`, not `program`.
    #[serde(rename = "data", default, with = "base64_bytes::vec")]
    pub program: Vec<u8>,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

// ---- Multisig routes ------------------------------------------------------

/// `POST /v1/multisig/list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigListRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
}

/// `POST /v1/multisig/import`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigImportRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "multisig_version", default)]
    pub version: u8,
    #[serde(rename = "threshold", default)]
    pub threshold: u8,
    /// Each pk is base64-encoded by the wire serializer.
    #[serde(rename = "pks", default, with = "vec_of_pks")]
    pub pks: Vec<APIV1PublicKey>,
}

/// `POST /v1/multisig/export`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigExportRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "address", default)]
    pub address: String,
}

/// `DELETE /v1/multisig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1DELETEMultisigRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "address", default)]
    pub address: String,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
}

/// `POST /v1/multisig/sign`. Mirrors
/// `APIV1POSTMultisigTransactionSignRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigTransactionSignRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,

    /// Base64-msgpack-encoded `Transaction`.
    #[serde(rename = "transaction", default, with = "base64_bytes::vec")]
    pub transaction: Vec<u8>,

    /// Public key of the signer within the multisig preimage.
    #[serde(
        rename = "public_key",
        default = "zero_pk",
        with = "base64_bytes::array_32"
    )]
    pub public_key: APIV1PublicKey,

    /// Partial multisig produced by other signers; we add our subsig
    /// and merge.
    #[serde(rename = "partial_multisig", default)]
    pub partial_msig: MultisigSig,

    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,

    /// Rekey/auth address — 32-byte digest, base64. All-zero means
    /// "no auth-addr override".
    #[serde(
        rename = "signer",
        default = "zero_pk",
        with = "base64_bytes::array_32"
    )]
    pub auth_addr: APIV1PublicKey,
}

impl Default for APIV1POSTMultisigTransactionSignRequest {
    fn default() -> Self {
        Self {
            wallet_handle_token: String::new(),
            transaction: Vec::new(),
            public_key: zero_pk(),
            partial_msig: MultisigSig::default(),
            wallet_password: String::new(),
            auth_addr: zero_pk(),
        }
    }
}

/// `POST /v1/multisig/signprogram`. Mirrors
/// `APIV1POSTMultisigProgramSignRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigProgramSignRequest {
    #[serde(rename = "wallet_handle_token", default)]
    pub wallet_handle_token: String,
    #[serde(rename = "address", default)]
    pub address: String,
    /// Note: Go's JSON tag is `data`, not `program`.
    #[serde(rename = "data", default, with = "base64_bytes::vec")]
    pub program: Vec<u8>,
    #[serde(
        rename = "public_key",
        default = "zero_pk",
        with = "base64_bytes::array_32"
    )]
    pub public_key: APIV1PublicKey,
    #[serde(rename = "partial_multisig", default)]
    pub partial_msig: MultisigSig,
    #[serde(rename = "wallet_password", default)]
    pub wallet_password: String,
    /// Whether to produce a "legacy" multisig signature (no auth-addr
    /// indirection). Mirrors Go's `UseLegacyMsig`.
    #[serde(rename = "use_legacy_msig", default)]
    pub use_legacy_msig: bool,
}

impl Default for APIV1POSTMultisigProgramSignRequest {
    fn default() -> Self {
        Self {
            wallet_handle_token: String::new(),
            address: String::new(),
            program: Vec::new(),
            public_key: zero_pk(),
            partial_msig: MultisigSig::default(),
            wallet_password: String::new(),
            use_legacy_msig: false,
        }
    }
}

// ---- helpers --------------------------------------------------------------

/// Adapter for `Vec<APIV1PublicKey>` (each pk base64-encoded). Lives
/// here rather than under `base64_bytes` because it's the only `Vec`
/// of fixed-size byte arrays we need.
mod vec_of_pks {
    use super::APIV1PublicKey;
    use crate::base64_bytes::array_32;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        v: &[APIV1PublicKey],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // Wrap each pk in a tiny struct so array_32::serialize fires.
        #[derive(Serialize)]
        struct Pk<'a>(#[serde(with = "array_32")] &'a [u8; 32]);
        let wrapped: Vec<Pk> = v.iter().map(Pk).collect();
        wrapped.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<APIV1PublicKey>, D::Error> {
        #[derive(Deserialize)]
        struct Pk(#[serde(with = "array_32")] [u8; 32]);
        let v: Vec<Pk> = Vec::deserialize(deserializer)?;
        Ok(v.into_iter().map(|p| p.0).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_init_request_round_trips() {
        let req = APIV1POSTWalletInitRequest::default();
        let json = serde_json::to_string(&req).unwrap();
        let back: APIV1POSTWalletInitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn partial_request_deserializes_with_defaults() {
        // Missing fields default to their zero value, matching Go's
        // json.Unmarshal behavior on plain struct types.
        let json = r#"{"wallet_name": "alpha"}"#;
        let req: APIV1POSTWalletRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.wallet_name, "alpha");
        assert_eq!(req.master_derivation_key, [0u8; 32]);
        assert_eq!(req.wallet_password, "");
    }

    #[test]
    fn multisig_pks_serialize_as_base64_array() {
        let req = APIV1POSTMultisigImportRequest {
            wallet_handle_token: "tok".into(),
            version: 1,
            threshold: 2,
            pks: vec![[0x40u8; 32], [0x41u8; 32]],
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        let pks = v["pks"].as_array().expect("pks is array");
        assert_eq!(pks.len(), 2);
        for pk in pks {
            let s = pk.as_str().expect("pk is base64 string");
            // Each base64-encoded 32 bytes -> 44 chars including padding.
            assert_eq!(s.len(), 44);
        }
    }
}
