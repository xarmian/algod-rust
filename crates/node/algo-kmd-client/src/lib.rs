//! REST client for kmd's v1 API. Mirrors
//! `../go-algorand/daemon/kmd/client/` at `v4.6.0-stable`:
//!
//! - `client.go` — `MakeKMDClient(addr, apiToken)` + `DoV1Request`.
//! - `requests.go` — `getPathAndMethod` route table (one (method, path)
//!   per typed request).
//! - `wrappers.go` — high-level methods that build the request type
//!   and call `DoV1Request`.
//!
//! Reuses [`algo_kmd_api_types`] for every wire shape so requests and
//! responses round-trip with the existing kmd server crate
//! ([`crates/node/algo-kmd`]) and Go's `kmd`.
//!
//! Phase-A scope (TASK-222 under PLAN-152): wallet + handle ops only
//! (versions, list-wallets, create, init, rename, release, info).
//!
//! Phase-B scope (TASK-233 under PLAN-232): key / multisig / sign /
//! program-sign / renew-handle wrappers used by `goal-rust account *`
//! and (eventually) `goal-rust clerk *`. Method names mirror Go's
//! `wrappers.go` verbatim, snake-cased. One Go gap intentionally
//! filled: `export_key` — kmdapi/requests.go has the route + types
//! but `wrappers.go` ships no client wrapper, and Phase B's `account
//! export` leaf needs it.
//!
//! ## Error mapping
//!
//! Go's `DoV1Request` decodes the JSON body, then calls
//! `resp.GetError()` which surfaces the embedded
//! `APIV1ResponseEnvelope{error: true, message: "..."}` as a Go error.
//! We do the same: any successful HTTP response whose JSON body has
//! `envelope.error == true` becomes [`KmdError::Api`] carrying the
//! message verbatim, so the goal-rust caller can print Go's exact
//! text. Transport-level failures (DNS, connect, 4xx/5xx with non-JSON
//! body) surface as [`KmdError::Http`] or [`KmdError::Decode`].

#![forbid(unsafe_code)]

use std::time::Duration;

use algo_kmd_api_types::{
    common::{APIV1PrivateKey, APIV1PublicKey, APIV1ResponseEnvelope, MultisigSig},
    requests::{
        APIV1DELETEKeyRequest, APIV1DELETEMultisigRequest, APIV1GETWalletsRequest,
        APIV1POSTKeyExportRequest, APIV1POSTKeyImportRequest, APIV1POSTKeyListRequest,
        APIV1POSTKeyRequest, APIV1POSTMasterKeyExportRequest, APIV1POSTMultisigExportRequest,
        APIV1POSTMultisigImportRequest, APIV1POSTMultisigListRequest,
        APIV1POSTMultisigProgramSignRequest, APIV1POSTMultisigTransactionSignRequest,
        APIV1POSTProgramSignRequest, APIV1POSTTransactionSignRequest, APIV1POSTWalletInfoRequest,
        APIV1POSTWalletInitRequest, APIV1POSTWalletReleaseRequest, APIV1POSTWalletRenameRequest,
        APIV1POSTWalletRenewRequest, APIV1POSTWalletRequest, VersionsRequest,
    },
    responses::{
        APIV1DELETEKeyResponse, APIV1DELETEMultisigResponse, APIV1GETWalletsResponse,
        APIV1POSTKeyExportResponse, APIV1POSTKeyImportResponse, APIV1POSTKeyListResponse,
        APIV1POSTKeyResponse, APIV1POSTMasterKeyExportResponse, APIV1POSTMultisigExportResponse,
        APIV1POSTMultisigImportResponse, APIV1POSTMultisigListResponse,
        APIV1POSTMultisigProgramSignResponse, APIV1POSTMultisigTransactionSignResponse,
        APIV1POSTProgramSignResponse, APIV1POSTTransactionSignResponse,
        APIV1POSTWalletInfoResponse, APIV1POSTWalletInitResponse, APIV1POSTWalletReleaseResponse,
        APIV1POSTWalletRenameResponse, APIV1POSTWalletRenewResponse, APIV1POSTWalletResponse,
        VersionsResponse,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use url::Url;

/// Header name carrying the pre-shared kmd API token. Tracks
/// `../go-algorand/daemon/kmd/api/v1/auth.go:29`
/// (`KMDTokenHeader = "X-KMD-API-Token"`).
pub const KMD_TOKEN_HEADER: &str = "X-KMD-API-Token";

/// Request timeout. Mirrors `client.go:25` (`timeoutSecs = 120`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// HTTP method + path for one of kmd's v1 routes.
/// `requests.go:getPathAndMethod` shape.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    method: reqwest::Method,
    path: &'static str,
}

fn versions_route() -> Route {
    Route {
        method: reqwest::Method::GET,
        path: "versions",
    }
}
fn wallets_list_route() -> Route {
    Route {
        method: reqwest::Method::GET,
        path: "v1/wallets",
    }
}
fn wallet_create_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet",
    }
}
fn wallet_init_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet/init",
    }
}
fn wallet_rename_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet/rename",
    }
}
fn wallet_release_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet/release",
    }
}
fn wallet_info_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet/info",
    }
}
fn wallet_renew_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/wallet/renew",
    }
}
fn master_key_export_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/master-key/export",
    }
}
fn key_generate_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/key",
    }
}
fn key_delete_route() -> Route {
    Route {
        method: reqwest::Method::DELETE,
        path: "v1/key",
    }
}
fn key_list_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/key/list",
    }
}
fn key_import_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/key/import",
    }
}
fn key_export_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/key/export",
    }
}
fn transaction_sign_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/transaction/sign",
    }
}
fn program_sign_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/program/sign",
    }
}
fn multisig_list_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/multisig/list",
    }
}
fn multisig_import_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/multisig/import",
    }
}
fn multisig_export_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/multisig/export",
    }
}
fn multisig_delete_route() -> Route {
    Route {
        method: reqwest::Method::DELETE,
        path: "v1/multisig",
    }
}
fn multisig_sign_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/multisig/sign",
    }
}
fn multisig_sign_program_route() -> Route {
    Route {
        method: reqwest::Method::POST,
        path: "v1/multisig/signprogram",
    }
}

/// Errors surfaced by [`KmdClient`].
#[derive(Debug, Error)]
pub enum KmdError {
    /// Constructor was given an address that isn't parseable.
    #[error("invalid kmd address `{addr}`: {message}")]
    InvalidAddress { addr: String, message: String },

    /// Transport-level failure (DNS, connect, body read, etc.).
    #[error("kmd transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// HTTP status was non-2xx and the body wasn't a valid v1 envelope
    /// (e.g. middleware returned plain-text 401).
    #[error("kmd request failed with HTTP {status}: {body}")]
    Status { status: u16, body: String },

    /// JSON decode failed for either request or response.
    #[error("kmd payload decode error: {0}")]
    Decode(#[from] serde_json::Error),

    /// kmd server-side error: response had `envelope.error: true`. The
    /// `message` is the literal text Go's kmd embeds. Callers print it
    /// to match `goal`'s output exactly.
    #[error("kmd API error: {message}")]
    Api { status: u16, message: String },
}

/// kmd v1 REST client. One instance per (address, token) pair.
///
/// Construct with [`KmdClient::new`]; addresses may be bare
/// `host:port` (as written into `kmd.net` by the daemon) or full
/// `http://host:port` URLs.
#[derive(Debug)]
pub struct KmdClient {
    base_url: Url,
    api_token: String,
    http: reqwest::Client,
}

impl KmdClient {
    /// Mirrors Go's `MakeKMDClient(address, apiToken)`. `address`
    /// accepts either a bare `host:port` or a full
    /// `http(s)://host:port` URL — the bare form matches what kmd
    /// writes into `kmd.net` and what Go's `DoV1Request` formats with
    /// `http://<addr>/<path>`.
    pub fn new(address: &str, api_token: &str) -> Result<Self, KmdError> {
        Self::with_http(address, api_token, default_http_client()?)
    }

    /// Test seam: supply a pre-built `reqwest::Client` (e.g. with
    /// custom TLS or a different timeout).
    pub fn with_http(
        address: &str,
        api_token: &str,
        http: reqwest::Client,
    ) -> Result<Self, KmdError> {
        let trimmed = address.trim();
        let needs_scheme = !trimmed.starts_with("http://") && !trimmed.starts_with("https://");
        let candidate = if needs_scheme {
            format!("http://{trimmed}")
        } else {
            trimmed.to_string()
        };
        let mut base_url = Url::parse(&candidate).map_err(|e| KmdError::InvalidAddress {
            addr: address.to_string(),
            message: e.to_string(),
        })?;
        // Ensure the base path ends with `/` so `Url::join` treats it
        // as a directory rather than overwriting the last segment.
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
            api_token: api_token.to_string(),
            http,
        })
    }

    /// Mirrors Go's `Version()` wrapper. `GET /versions`. Unlike the
    /// rest of v1, this endpoint is unauthenticated server-side, but
    /// Go still attaches the token header — we match.
    pub async fn versions(&self) -> Result<VersionsResponse, KmdError> {
        // VersionsResponse lacks the v1 envelope (responses.go:52), so
        // we can't run the same envelope.error check as the other
        // routes. Decode directly and surface non-2xx via Status.
        let url = self.join(versions_route().path)?;
        let resp = self
            .http
            .request(reqwest::Method::GET, url)
            .header(KMD_TOKEN_HEADER, &self.api_token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&VersionsRequest::default())?)
            .send()
            .await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(KmdError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Mirrors `ListWallets()`. `GET /v1/wallets`.
    pub async fn list_wallets(&self) -> Result<APIV1GETWalletsResponse, KmdError> {
        self.do_request(wallets_list_route(), &APIV1GETWalletsRequest::default())
            .await
    }

    /// Mirrors `CreateWallet(walletName, walletDriverName,
    /// walletPassword, walletMDK)`. `POST /v1/wallet`.
    ///
    /// `mdk` is the optional 32-byte master derivation key (an
    /// all-zero array means "generate a new one server-side", matching
    /// Go's behavior when the field is left default).
    pub async fn create_wallet(
        &self,
        name: &str,
        driver: &str,
        password: &str,
        mdk: [u8; 32],
    ) -> Result<APIV1POSTWalletResponse, KmdError> {
        let req = APIV1POSTWalletRequest {
            wallet_name: name.to_string(),
            wallet_driver_name: driver.to_string(),
            wallet_password: password.to_string(),
            master_derivation_key: mdk,
        };
        self.do_request(wallet_create_route(), &req).await
    }

    /// Mirrors `InitWallet(walletID, walletPassword)`.
    /// `POST /v1/wallet/init`.
    pub async fn init_wallet(
        &self,
        wallet_id: &str,
        wallet_password: &str,
    ) -> Result<APIV1POSTWalletInitResponse, KmdError> {
        let req = APIV1POSTWalletInitRequest {
            wallet_id: wallet_id.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(wallet_init_route(), &req).await
    }

    /// Mirrors `RenameWallet(walletID, newWalletName, walletPassword)`.
    /// `POST /v1/wallet/rename`.
    pub async fn rename_wallet(
        &self,
        wallet_id: &str,
        new_name: &str,
        wallet_password: &str,
    ) -> Result<APIV1POSTWalletRenameResponse, KmdError> {
        let req = APIV1POSTWalletRenameRequest {
            wallet_id: wallet_id.to_string(),
            new_wallet_name: new_name.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(wallet_rename_route(), &req).await
    }

    /// Mirrors `ReleaseWalletHandle(walletHandle)`.
    /// `POST /v1/wallet/release`.
    pub async fn release_wallet_handle(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTWalletReleaseResponse, KmdError> {
        let req = APIV1POSTWalletReleaseRequest {
            wallet_handle_token: wallet_handle.to_string(),
        };
        self.do_request(wallet_release_route(), &req).await
    }

    /// Mirrors the `walletInfo` helper that goal-rust's
    /// `wallet`/`account` subcommands use to look up a wallet's
    /// metadata by handle. `POST /v1/wallet/info`.
    pub async fn wallet_info(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTWalletInfoResponse, KmdError> {
        let req = APIV1POSTWalletInfoRequest {
            wallet_handle_token: wallet_handle.to_string(),
        };
        self.do_request(wallet_info_route(), &req).await
    }

    /// Mirrors `RenewWalletHandle(walletHandle)`.
    /// `POST /v1/wallet/renew`. Bumps the server-side expiry on an
    /// existing handle without re-prompting the user for the wallet
    /// password.
    pub async fn renew_wallet_handle(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTWalletRenewResponse, KmdError> {
        let req = APIV1POSTWalletRenewRequest {
            wallet_handle_token: wallet_handle.to_string(),
        };
        self.do_request(wallet_renew_route(), &req).await
    }

    /// Mirrors `ExportMasterDerivationKey(walletHandle, walletPassword)`.
    /// `POST /v1/master-key/export`. Returns the wallet's 32-byte MDK
    /// so it can be rendered as a mnemonic by the caller.
    pub async fn master_key_export(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
    ) -> Result<APIV1POSTMasterKeyExportResponse, KmdError> {
        let req = APIV1POSTMasterKeyExportRequest {
            wallet_handle_token: wallet_handle.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(master_key_export_route(), &req).await
    }

    /// Mirrors `GenerateKey(walletHandle)`. `POST /v1/key`. The SQLite
    /// driver always rejects `display_mnemonic=true` (sqlite.go:850,
    /// `errNoMnemonicUX`), so we pin it to `false` — matching the call
    /// site Go's `goal account new` uses.
    pub async fn generate_key(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTKeyResponse, KmdError> {
        let req = APIV1POSTKeyRequest {
            wallet_handle_token: wallet_handle.to_string(),
            display_mnemonic: false,
        };
        self.do_request(key_generate_route(), &req).await
    }

    /// Mirrors `ListKeys(walletHandle)`. `POST /v1/key/list`. Returns
    /// every public address held by the wallet (32-byte pubkeys formatted
    /// as Algorand base32 strings).
    pub async fn list_keys(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTKeyListResponse, KmdError> {
        let req = APIV1POSTKeyListRequest {
            wallet_handle_token: wallet_handle.to_string(),
        };
        self.do_request(key_list_route(), &req).await
    }

    /// Mirrors `ImportKey(walletHandle, secretKey)`. `POST /v1/key/import`.
    /// `secret_key` is the 64-byte Ed25519 expanded private key (the
    /// same shape Go's `crypto.PrivateKey` carries).
    pub async fn import_key(
        &self,
        wallet_handle: &str,
        secret_key: APIV1PrivateKey,
    ) -> Result<APIV1POSTKeyImportResponse, KmdError> {
        let req = APIV1POSTKeyImportRequest {
            wallet_handle_token: wallet_handle.to_string(),
            private_key: secret_key,
        };
        self.do_request(key_import_route(), &req).await
    }

    /// `POST /v1/key/export`. Returns the 64-byte expanded private key
    /// for `address`. NOTE: Go's `wrappers.go` ships no `ExportKey`
    /// wrapper, but the route + request/response types are defined in
    /// `kmdapi/{requests,responses}.go` and kmd-rust serves the route.
    /// Phase B's `goal account export` consumes this method directly.
    pub async fn export_key(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        address: &str,
    ) -> Result<APIV1POSTKeyExportResponse, KmdError> {
        let req = APIV1POSTKeyExportRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(key_export_route(), &req).await
    }

    /// Mirrors `DeleteKey(walletHandle, pw, addr)`. `DELETE /v1/key`.
    /// Removes the key for `address` from the wallet. Server validates
    /// the password before deletion.
    pub async fn delete_key(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        address: &str,
    ) -> Result<APIV1DELETEKeyResponse, KmdError> {
        let req = APIV1DELETEKeyRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(key_delete_route(), &req).await
    }

    /// Mirrors `SignTransaction(walletHandle, pw, pk, tx)`.
    /// `POST /v1/transaction/sign`.
    ///
    /// Unlike Go's wrapper — which takes a `transactions.Transaction`
    /// struct and msgpack-encodes it internally — this client takes
    /// **pre-encoded** canonical msgpack bytes so the kmd-client crate
    /// stays independent of `algo-types`. Callers (goal-rust, clerk)
    /// already have a `Transaction` and run it through
    /// `algo_codec::canonical_encode_transaction`. The wire field is
    /// `transaction` either way.
    ///
    /// `signer` is the 32-byte public key to sign with; passing
    /// `[0u8; 32]` matches Go's "infer the signer from `txn.snd`"
    /// behavior at the sqlite-driver call site.
    pub async fn sign_transaction(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        transaction: Vec<u8>,
        signer: APIV1PublicKey,
    ) -> Result<APIV1POSTTransactionSignResponse, KmdError> {
        let req = APIV1POSTTransactionSignRequest {
            wallet_handle_token: wallet_handle.to_string(),
            transaction,
            public_key: signer,
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(transaction_sign_route(), &req).await
    }

    /// Mirrors `SignProgram(walletHandle, pw, addr, data)`.
    /// `POST /v1/program/sign`. Signs `program` under the key for
    /// `address`. Returns a raw 64-byte Ed25519 signature over
    /// `"Program" || program` (the LogicSig signing rule).
    pub async fn sign_program(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        address: &str,
        program: Vec<u8>,
    ) -> Result<APIV1POSTProgramSignResponse, KmdError> {
        let req = APIV1POSTProgramSignRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
            program,
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(program_sign_route(), &req).await
    }

    /// Mirrors `ListMultisigAddrs(walletHandle)`.
    /// `POST /v1/multisig/list`. Returns the base32 addresses of every
    /// multisig preimage held by the wallet.
    pub async fn list_multisig_addrs(
        &self,
        wallet_handle: &str,
    ) -> Result<APIV1POSTMultisigListResponse, KmdError> {
        let req = APIV1POSTMultisigListRequest {
            wallet_handle_token: wallet_handle.to_string(),
        };
        self.do_request(multisig_list_route(), &req).await
    }

    /// Mirrors `ImportMultisigAddr(walletHandle, version, threshold, pks)`.
    /// `POST /v1/multisig/import`. Stores the multisig preimage and
    /// returns the derived multisig address.
    pub async fn import_multisig(
        &self,
        wallet_handle: &str,
        version: u8,
        threshold: u8,
        pks: Vec<APIV1PublicKey>,
    ) -> Result<APIV1POSTMultisigImportResponse, KmdError> {
        let req = APIV1POSTMultisigImportRequest {
            wallet_handle_token: wallet_handle.to_string(),
            version,
            threshold,
            pks,
        };
        self.do_request(multisig_import_route(), &req).await
    }

    /// Mirrors `ExportMultisigAddr(walletHandle, addr)`.
    /// `POST /v1/multisig/export`. Returns the version / threshold /
    /// pks that derive `address`.
    pub async fn export_multisig(
        &self,
        wallet_handle: &str,
        address: &str,
    ) -> Result<APIV1POSTMultisigExportResponse, KmdError> {
        let req = APIV1POSTMultisigExportRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
        };
        self.do_request(multisig_export_route(), &req).await
    }

    /// Mirrors `DeleteMultisigAddr(walletHandle, pw, addr)`.
    /// `DELETE /v1/multisig`. Drops the multisig preimage; the
    /// underlying component keys are untouched.
    pub async fn delete_multisig(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        address: &str,
    ) -> Result<APIV1DELETEMultisigResponse, KmdError> {
        let req = APIV1DELETEMultisigRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
            wallet_password: wallet_password.to_string(),
        };
        self.do_request(multisig_delete_route(), &req).await
    }

    /// Mirrors `MultisigSignTransaction(walletHandle, pw, tx, pk,
    /// partial, msigSigner)`. `POST /v1/multisig/sign`.
    ///
    /// As with `sign_transaction`, `transaction` is **pre-encoded**
    /// canonical msgpack bytes. `public_key` is the component pubkey
    /// for our subsig; `partial_msig` is the in-progress multisig (or
    /// `MultisigSig::default()` if we're the first signer);
    /// `auth_addr` is the rekey/auth address (all-zero means none).
    pub async fn multisig_sign_transaction(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        transaction: Vec<u8>,
        public_key: APIV1PublicKey,
        partial_msig: MultisigSig,
        auth_addr: APIV1PublicKey,
    ) -> Result<APIV1POSTMultisigTransactionSignResponse, KmdError> {
        let req = APIV1POSTMultisigTransactionSignRequest {
            wallet_handle_token: wallet_handle.to_string(),
            transaction,
            public_key,
            partial_msig,
            wallet_password: wallet_password.to_string(),
            auth_addr,
        };
        self.do_request(multisig_sign_route(), &req).await
    }

    /// Mirrors `MultisigSignProgram(walletHandle, pw, addr, data, pk,
    /// partial, useLegacyMsig)`. `POST /v1/multisig/signprogram`.
    #[allow(clippy::too_many_arguments)] // mirrors Go's 7-arg wrapper verbatim
    pub async fn multisig_sign_program(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        address: &str,
        public_key: APIV1PublicKey,
        partial_msig: MultisigSig,
        program: Vec<u8>,
        use_legacy_msig: bool,
    ) -> Result<APIV1POSTMultisigProgramSignResponse, KmdError> {
        let req = APIV1POSTMultisigProgramSignRequest {
            wallet_handle_token: wallet_handle.to_string(),
            address: address.to_string(),
            program,
            public_key,
            partial_msig,
            wallet_password: wallet_password.to_string(),
            use_legacy_msig,
        };
        self.do_request(multisig_sign_program_route(), &req).await
    }

    fn join(&self, path: &str) -> Result<Url, KmdError> {
        // `Url::join` treats the LHS as a base — by ensuring `path`
        // never starts with `/` and the base ends with `/`, we always
        // get `http://addr/<path>`.
        self.base_url
            .join(path)
            .map_err(|e| KmdError::InvalidAddress {
                addr: self.base_url.to_string(),
                message: e.to_string(),
            })
    }

    async fn do_request<Req, Resp>(&self, route: Route, body: &Req) -> Result<Resp, KmdError>
    where
        Req: Serialize,
        Resp: DeserializeOwned + Envelope,
    {
        let url = self.join(route.path)?;
        let mut req_builder = self.http.request(route.method.clone(), url);
        req_builder = req_builder.header(KMD_TOKEN_HEADER, &self.api_token);
        // Go's DoV1Request always encodes the request body as JSON
        // (`protocol.EncodeJSON(req)`) and sends it — even for GETs.
        // Most GET routes have empty-struct request types; `body` is
        // `{}` in that case. Matching that wire shape keeps us
        // round-trip-compatible with kmd servers that expect a body.
        let payload = serde_json::to_vec(body)?;
        req_builder = req_builder
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(payload);

        let resp = req_builder.send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;

        // Try to parse as a typed v1 response first — even on non-2xx,
        // kmd usually returns the v1 envelope, and we want to surface
        // the embedded `message` rather than a generic HTTP error.
        match serde_json::from_slice::<Resp>(&bytes) {
            Ok(parsed) => {
                let env = parsed.envelope();
                if env.error {
                    Err(KmdError::Api {
                        status: status.as_u16(),
                        message: env.message.clone(),
                    })
                } else if !status.is_success() {
                    // Body parsed but no embedded error and the status
                    // was 4xx/5xx — surface the status so the caller
                    // can decide what to do.
                    Err(KmdError::Status {
                        status: status.as_u16(),
                        body: String::from_utf8_lossy(&bytes).into_owned(),
                    })
                } else {
                    Ok(parsed)
                }
            }
            Err(decode_err) => {
                if !status.is_success() {
                    Err(KmdError::Status {
                        status: status.as_u16(),
                        body: String::from_utf8_lossy(&bytes).into_owned(),
                    })
                } else {
                    Err(KmdError::Decode(decode_err))
                }
            }
        }
    }
}

fn default_http_client() -> Result<reqwest::Client, KmdError> {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(KmdError::Http)
}

/// Internal trait giving us uniform access to the embedded
/// [`APIV1ResponseEnvelope`] across every typed kmd response.
trait Envelope {
    fn envelope(&self) -> &APIV1ResponseEnvelope;
}

macro_rules! impl_envelope {
    ($($t:ty),+ $(,)?) => {
        $(
            impl Envelope for $t {
                fn envelope(&self) -> &APIV1ResponseEnvelope {
                    &self.envelope
                }
            }
        )+
    };
}

// VersionsResponse intentionally omitted — Go's responses.go:52
// declares it without the envelope.
impl_envelope! {
    APIV1GETWalletsResponse,
    APIV1POSTWalletResponse,
    APIV1POSTWalletInitResponse,
    APIV1POSTWalletReleaseResponse,
    APIV1POSTWalletRenameResponse,
    APIV1POSTWalletInfoResponse,
    APIV1POSTWalletRenewResponse,
    APIV1POSTMasterKeyExportResponse,
    APIV1POSTKeyResponse,
    APIV1DELETEKeyResponse,
    APIV1POSTKeyListResponse,
    APIV1POSTKeyImportResponse,
    APIV1POSTKeyExportResponse,
    APIV1POSTTransactionSignResponse,
    APIV1POSTProgramSignResponse,
    APIV1POSTMultisigListResponse,
    APIV1POSTMultisigImportResponse,
    APIV1POSTMultisigExportResponse,
    APIV1DELETEMultisigResponse,
    APIV1POSTMultisigTransactionSignResponse,
    APIV1POSTMultisigProgramSignResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table_matches_go_requests_go() {
        // Regression guard: the (method, path) pairs MUST match
        // `daemon/kmd/client/requests.go:getPathAndMethod`. Hand-typed
        // to catch accidental wandering.
        for (got, want_method, want_path) in [
            (versions_route(), reqwest::Method::GET, "versions"),
            (wallets_list_route(), reqwest::Method::GET, "v1/wallets"),
            (wallet_create_route(), reqwest::Method::POST, "v1/wallet"),
            (wallet_init_route(), reqwest::Method::POST, "v1/wallet/init"),
            (
                wallet_rename_route(),
                reqwest::Method::POST,
                "v1/wallet/rename",
            ),
            (
                wallet_release_route(),
                reqwest::Method::POST,
                "v1/wallet/release",
            ),
            (wallet_info_route(), reqwest::Method::POST, "v1/wallet/info"),
            (
                wallet_renew_route(),
                reqwest::Method::POST,
                "v1/wallet/renew",
            ),
            (
                master_key_export_route(),
                reqwest::Method::POST,
                "v1/master-key/export",
            ),
            (key_generate_route(), reqwest::Method::POST, "v1/key"),
            (key_delete_route(), reqwest::Method::DELETE, "v1/key"),
            (key_list_route(), reqwest::Method::POST, "v1/key/list"),
            (key_import_route(), reqwest::Method::POST, "v1/key/import"),
            (key_export_route(), reqwest::Method::POST, "v1/key/export"),
            (
                transaction_sign_route(),
                reqwest::Method::POST,
                "v1/transaction/sign",
            ),
            (
                program_sign_route(),
                reqwest::Method::POST,
                "v1/program/sign",
            ),
            (
                multisig_list_route(),
                reqwest::Method::POST,
                "v1/multisig/list",
            ),
            (
                multisig_import_route(),
                reqwest::Method::POST,
                "v1/multisig/import",
            ),
            (
                multisig_export_route(),
                reqwest::Method::POST,
                "v1/multisig/export",
            ),
            (
                multisig_delete_route(),
                reqwest::Method::DELETE,
                "v1/multisig",
            ),
            (
                multisig_sign_route(),
                reqwest::Method::POST,
                "v1/multisig/sign",
            ),
            (
                multisig_sign_program_route(),
                reqwest::Method::POST,
                "v1/multisig/signprogram",
            ),
        ] {
            assert_eq!(got.method, want_method, "method for {want_path}");
            assert_eq!(got.path, want_path, "path for {want_path}");
        }
    }

    #[test]
    fn bare_address_gets_http_scheme_prepended() {
        let c = KmdClient::new("127.0.0.1:7833", "tok").unwrap();
        assert_eq!(c.base_url.as_str(), "http://127.0.0.1:7833/");
    }

    #[test]
    fn explicit_scheme_is_preserved() {
        let c = KmdClient::new("https://kmd.example.com", "tok").unwrap();
        assert_eq!(c.base_url.as_str(), "https://kmd.example.com/");
    }

    #[test]
    fn invalid_address_returns_invalid_address_error() {
        let err = KmdClient::new("http://[not-a-valid-uri", "tok").unwrap_err();
        assert!(matches!(err, KmdError::InvalidAddress { .. }));
    }

    #[test]
    fn route_join_produces_expected_url() {
        let c = KmdClient::new("127.0.0.1:7833", "tok").unwrap();
        let joined = c.base_url.join("v1/wallet/init").unwrap();
        assert_eq!(joined.as_str(), "http://127.0.0.1:7833/v1/wallet/init");
    }
}
