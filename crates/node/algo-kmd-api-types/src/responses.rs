//! v1 response body shapes. Ported from
//! `daemon/kmd/lib/kmdapi/responses.go`.
//!
//! Every `APIV1*Response` embeds [`APIV1ResponseEnvelope`] (via serde
//! `flatten`) so the `error` / `message` fields appear at the top
//! level of the JSON, matching Go's struct-embedding behavior.
//!
//! ## Empty-field omission
//!
//! Go embeds `APIV1ResponseEnvelope` which carries the directive
//! `_struct codec:",omitempty,omitemptyarray"`. In go-codec this
//! propagates *to the entire embedding struct*: any field of an
//! envelope-embedding response that holds its type's zero value is
//! omitted from the JSON output. We mirror that with
//! `skip_serializing_if = "..."` on every response field at this
//! layer. Nested structs that don't embed the envelope (e.g.
//! [`APIV1Wallet`]) keep all their fields per Go.

use serde::{Deserialize, Serialize};

use crate::base64_bytes;
use crate::common::{
    APIV1MasterDerivationKey, APIV1PrivateKey, APIV1PublicKey, APIV1ResponseEnvelope, APIV1Wallet,
    APIV1WalletHandle,
};

// ---- skip-if-empty helpers ------------------------------------------------

fn is_zero_u8(n: &u8) -> bool {
    *n == 0
}

fn is_zero_array_32(a: &[u8; 32]) -> bool {
    a.iter().all(|&b| b == 0)
}

fn is_zero_array_64(a: &[u8; 64]) -> bool {
    a.iter().all(|&b| b == 0)
}

fn is_default_wallet(w: &APIV1Wallet) -> bool {
    *w == APIV1Wallet::default()
}

fn is_default_wallet_handle(h: &APIV1WalletHandle) -> bool {
    *h == APIV1WalletHandle::default()
}

// ---- /versions ------------------------------------------------------------

/// `GET /versions` — server version strings. Lacks the response
/// envelope per Go (responses.go:52).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionsResponse {
    #[serde(rename = "versions", default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
}

// ---- Wallet routes --------------------------------------------------------

/// `GET /v1/wallets`. Mirrors `APIV1GETWalletsResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1GETWalletsResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "wallets", default, skip_serializing_if = "Vec::is_empty")]
    pub wallets: Vec<APIV1Wallet>,
}

/// `POST /v1/wallet`. Mirrors `APIV1POSTWalletResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "wallet", default, skip_serializing_if = "is_default_wallet")]
    pub wallet: APIV1Wallet,
}

/// `POST /v1/wallet/init`. Mirrors `APIV1POSTWalletInitResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletInitResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "wallet_handle_token",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub wallet_handle_token: String,
}

/// `POST /v1/wallet/release`. Empty body besides the envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletReleaseResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
}

/// `POST /v1/wallet/renew`. Mirrors `APIV1POSTWalletRenewResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletRenewResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "wallet_handle",
        default,
        skip_serializing_if = "is_default_wallet_handle"
    )]
    pub wallet_handle: APIV1WalletHandle,
}

/// `POST /v1/wallet/rename`. Mirrors `APIV1POSTWalletRenameResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletRenameResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "wallet", default, skip_serializing_if = "is_default_wallet")]
    pub wallet: APIV1Wallet,
}

/// `POST /v1/wallet/info`. Mirrors `APIV1POSTWalletInfoResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTWalletInfoResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "wallet_handle",
        default,
        skip_serializing_if = "is_default_wallet_handle"
    )]
    pub wallet_handle: APIV1WalletHandle,
}

/// `POST /v1/master-key/export`. Mirrors
/// `APIV1POSTMasterKeyExportResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMasterKeyExportResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "master_derivation_key",
        default = "zero_mdk",
        skip_serializing_if = "is_zero_array_32",
        with = "base64_bytes::array_32"
    )]
    pub master_derivation_key: APIV1MasterDerivationKey,
}

fn zero_mdk() -> APIV1MasterDerivationKey {
    [0u8; 32]
}

// [u8; 32] derives Default to all zeros, but the explicit impl keeps
// the structure consistent with APIV1POSTKeyExportResponse below (whose
// [u8; 64] field doesn't have a derived Default at the time of writing).
impl Default for APIV1POSTMasterKeyExportResponse {
    fn default() -> Self {
        Self {
            envelope: APIV1ResponseEnvelope::default(),
            master_derivation_key: zero_mdk(),
        }
    }
}

// ---- Key routes -----------------------------------------------------------

/// `POST /v1/key/import`. Mirrors `APIV1POSTKeyImportResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyImportResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "address", default, skip_serializing_if = "String::is_empty")]
    pub address: String,
}

/// `POST /v1/key/export`. Mirrors `APIV1POSTKeyExportResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyExportResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "private_key",
        default = "zero_sk",
        skip_serializing_if = "is_zero_array_64",
        with = "base64_bytes::array_64"
    )]
    pub private_key: APIV1PrivateKey,
}

fn zero_sk() -> APIV1PrivateKey {
    [0u8; 64]
}

// `[u8; 64]` does not implement `Default` (const-generics Default only
// covers 0..=32), so we provide it manually rather than deriving.
impl Default for APIV1POSTKeyExportResponse {
    fn default() -> Self {
        Self {
            envelope: APIV1ResponseEnvelope::default(),
            private_key: zero_sk(),
        }
    }
}

/// `POST /v1/key`. Mirrors `APIV1POSTKeyResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "address", default, skip_serializing_if = "String::is_empty")]
    pub address: String,
}

/// `DELETE /v1/key`. Empty body besides the envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1DELETEKeyResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
}

/// `POST /v1/key/list`. Mirrors `APIV1POSTKeyListResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTKeyListResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "addresses", default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

// ---- Sign routes ----------------------------------------------------------

/// `POST /v1/transaction/sign`. Mirrors
/// `APIV1POSTTransactionSignResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTTransactionSignResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    /// Msgpack-encoded `SignedTransaction` (variable length),
    /// base64-encoded on the JSON wire.
    #[serde(
        rename = "signed_transaction",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes::vec"
    )]
    pub signed_transaction: Vec<u8>,
}

/// `POST /v1/program/sign`. Mirrors `APIV1POSTProgramSignResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTProgramSignResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    /// Raw 64-byte Ed25519 signature. Modeled as `Vec<u8>` because Go
    /// uses `[]byte` (sized by convention but not by the wire type).
    #[serde(
        rename = "sig",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes::vec"
    )]
    pub signature: Vec<u8>,
}

// ---- Multisig routes ------------------------------------------------------

/// `POST /v1/multisig/list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigListResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "addresses", default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

/// `POST /v1/multisig/import`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigImportResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(rename = "address", default, skip_serializing_if = "String::is_empty")]
    pub address: String,
}

/// `POST /v1/multisig/export`. Mirrors
/// `APIV1POSTMultisigExportResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigExportResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "multisig_version",
        default,
        skip_serializing_if = "is_zero_u8"
    )]
    pub version: u8,
    #[serde(rename = "threshold", default, skip_serializing_if = "is_zero_u8")]
    pub threshold: u8,
    #[serde(
        rename = "pks",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "vec_of_pks"
    )]
    pub pks: Vec<APIV1PublicKey>,
}

/// `DELETE /v1/multisig`. Empty body besides the envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1DELETEMultisigResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
}

/// `POST /v1/multisig/sign`. Mirrors
/// `APIV1POSTMultisigTransactionSignResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigTransactionSignResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    /// Msgpack-encoded `MultisigSig`, base64 on the JSON wire.
    #[serde(
        rename = "multisig",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes::vec"
    )]
    pub multisig: Vec<u8>,
}

/// `POST /v1/multisig/signprogram`. Mirrors
/// `APIV1POSTMultisigProgramSignResponse`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct APIV1POSTMultisigProgramSignResponse {
    #[serde(flatten)]
    pub envelope: APIV1ResponseEnvelope,
    #[serde(
        rename = "multisig",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "base64_bytes::vec"
    )]
    pub multisig: Vec<u8>,
}

// ---- helpers --------------------------------------------------------------

mod vec_of_pks {
    use super::APIV1PublicKey;
    use crate::base64_bytes::array_32;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        v: &[APIV1PublicKey],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
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
    fn success_response_omits_empty_envelope_fields() {
        let r = APIV1POSTMasterKeyExportResponse {
            envelope: APIV1ResponseEnvelope::default(),
            master_derivation_key: std::array::from_fn(|i| i as u8 + 1),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(v.get("error").is_none(), "default error should be skipped");
        assert!(
            v.get("message").is_none(),
            "default message should be skipped"
        );
        assert!(v["master_derivation_key"].is_string());
    }

    #[test]
    fn error_response_includes_envelope_fields() {
        let r = APIV1POSTWalletInitResponse {
            envelope: APIV1ResponseEnvelope {
                error: true,
                message: "wrong password".into(),
            },
            wallet_handle_token: String::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["error"], true);
        assert_eq!(v["message"], "wrong password");
        // Empty wallet_handle_token must be omitted to match Go (the
        // envelope's _struct directive propagates to all fields of
        // the embedding response).
        assert!(v.get("wallet_handle_token").is_none());
    }

    #[test]
    fn versions_response_round_trips() {
        let r = VersionsResponse {
            versions: vec!["v1".into()],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: VersionsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
