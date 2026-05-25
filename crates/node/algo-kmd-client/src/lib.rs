//! REST client for kmd's v1 API. Mirrors
//! `../go-algorand/daemon/kmd/client/` at `v4.5.1-stable`:
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
//! (versions, list-wallets, create, init, rename, release, info). Key
//! / multisig / sign methods land in Phase B alongside the
//! `account` / `clerk` subcommands of `goal-rust`.
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
    common::APIV1ResponseEnvelope,
    requests::{
        APIV1GETWalletsRequest, APIV1POSTWalletInfoRequest, APIV1POSTWalletInitRequest,
        APIV1POSTWalletReleaseRequest, APIV1POSTWalletRenameRequest, APIV1POSTWalletRequest,
        VersionsRequest,
    },
    responses::{
        APIV1GETWalletsResponse, APIV1POSTWalletInfoResponse, APIV1POSTWalletInitResponse,
        APIV1POSTWalletReleaseResponse, APIV1POSTWalletRenameResponse, APIV1POSTWalletResponse,
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
