//! v1 REST handlers — ported from
//! `../go-algorand/daemon/kmd/api/v1/handlers.go` (v4.5.1-stable).
//!
//! Phase B / B5 lands the 8 wallet handlers; B6/B7/B8 will extend
//! this module with key, multisig, and sign routes by registering
//! more routes on the [`router`] returned here.
//!
//! ## Response envelope
//!
//! Every v1 success returns 200 with an `APIV1*Response` whose
//! embedded [`APIV1ResponseEnvelope`] is empty (default).  Every
//! failure returns the Go-mapped HTTP status (400 / 401 / 500) with
//! an envelope-only body: `{"error":true,"message":"<go text>"}` —
//! the message text mirrors what Go writes via `errorResponse(w,
//! status, err)` (`api/v1/handlers.go:44`), pulling text from the
//! named errors in `daemon/kmd/wallet/driver/sqlite_errors.go` and
//! the local sentinels in `api/v1/errors.go`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use algo_kmd_api_types::common::{APIV1ResponseEnvelope, APIV1Wallet, APIV1WalletHandle};
use algo_kmd_api_types::requests::{
    APIV1DELETEKeyRequest, APIV1POSTKeyExportRequest, APIV1POSTKeyImportRequest,
    APIV1POSTKeyListRequest, APIV1POSTKeyRequest, APIV1POSTMasterKeyExportRequest,
    APIV1POSTWalletInfoRequest, APIV1POSTWalletInitRequest, APIV1POSTWalletReleaseRequest,
    APIV1POSTWalletRenameRequest, APIV1POSTWalletRenewRequest, APIV1POSTWalletRequest,
};
use algo_kmd_api_types::responses::{
    APIV1DELETEKeyResponse, APIV1GETWalletsResponse, APIV1POSTKeyExportResponse,
    APIV1POSTKeyImportResponse, APIV1POSTKeyListResponse, APIV1POSTKeyResponse,
    APIV1POSTMasterKeyExportResponse, APIV1POSTWalletInfoResponse, APIV1POSTWalletInitResponse,
    APIV1POSTWalletReleaseResponse, APIV1POSTWalletRenameResponse, APIV1POSTWalletRenewResponse,
    APIV1POSTWalletResponse,
};
use algo_types::Address;

use crate::error::Error;
use crate::session::SessionManager;
use crate::sqlite::WalletMetadata;
use crate::wallet::WalletDriver;

/// SQLite driver's `wallet.Metadata.SupportsMnemonicUX` — hard-coded
/// `false` (`daemon/kmd/wallet/driver/sqlite.go:50`).
const SQLITE_SUPPORTS_MNEMONIC_UX: bool = false;
/// SQLite driver's `wallet.Metadata.DriverName` — always `"sqlite"`.
const SQLITE_WALLET_DRIVER_NAME: &str = crate::sqlite::SQLITE_WALLET_DRIVER_NAME;
/// SQLite driver's `wallet.Metadata.SupportedTransactions` — hard-
/// coded `[]protocol.TxType{PaymentTx, KeyRegistrationTx}` at
/// `daemon/kmd/wallet/driver/sqlite.go:54`.  Strings are the on-wire
/// tags from `protocol/txntype.go`.
const SQLITE_SUPPORTED_TXS: &[&str] = &["pay", "keyreg"];

/// `walletIDBytes = 16` (`daemon/kmd/wallet/wallet.go:29`).  We emit
/// a 32-char lowercase-hex ID by encoding 16 random bytes.
const WALLET_ID_BYTES: usize = 16;

/// Shared state injected into every v1 handler.  Cheap to clone —
/// the underlying driver / session manager / token live inside `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub session_manager: Arc<SessionManager>,
    pub wallet_driver: Arc<WalletDriver>,
}

/// Build the v1 router.  Caller (`server.rs`) nests this under
/// `/v1` after stacking the bearer-token auth middleware on top.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Wallet routes (B5)
        .route("/wallets", axum::routing::get(get_wallets))
        .route("/wallet", post(post_wallet))
        .route("/wallet/init", post(post_wallet_init))
        .route("/wallet/release", post(post_wallet_release))
        .route("/wallet/renew", post(post_wallet_renew))
        .route("/wallet/rename", post(post_wallet_rename))
        .route("/wallet/info", post(post_wallet_info))
        .route("/master-key/export", post(post_master_key_export))
        // Key routes (B6)
        .route("/key", post(post_key).delete(delete_key))
        .route("/key/list", post(post_key_list))
        .route("/key/import", post(post_key_import))
        .route("/key/export", post(post_key_export))
        .with_state(state)
}

// ---------------------------------------------------------------- error mapping

/// Map an [`Error`] to the HTTP status code + user-readable message
/// Go would emit via `errorResponse(w, status, err)` for the same
/// underlying condition.
///
/// Sources:
/// - `daemon/kmd/wallet/driver/sqlite_errors.go` (`errWrongPassword`
///   etc. — `"wrong password"` is `errDecrypt.Error()` at sqlite_
///   errors.go:21).
/// - `daemon/kmd/session/auth.go` ("invalid wallet handle id" etc.).
/// - `daemon/kmd/api/v1/errors.go` (`errCouldNotDecode`).
/// - `daemon/kmd/api/v1/handlers.go` per-handler status choices —
///   400 for "bad request"-ish errors (driver/wallet not found,
///   wrong password on rename, etc.), 401 for handle-token / wallet-
///   init password failures, 500 for genuine internal failures.
///
/// The status mapping reflects each call site in Go.  Callers that
/// need a different status for the same `Error` value override it
/// (e.g. wallet-init's wrong-password is 401, but
/// master-key-export's wrong-password is 400 — matching Go at lines
/// 245 and 354 of `handlers.go`).
pub fn status_for_error(err: &Error) -> StatusCode {
    match err {
        // 401 — wallet-handle auth failures.
        Error::WalletHandleInvalid | Error::WalletHandleExpired => StatusCode::UNAUTHORIZED,
        // 400 — request-shape or driver/lookup failures.
        Error::WalletNotFound
        | Error::IdConflict
        | Error::SameName
        | Error::SameId
        | Error::WalletExists(_)
        | Error::NameTooLong
        | Error::IdTooLong
        | Error::WrongDriver
        | Error::WrongDriverVersion
        | Error::MultisigInvalid
        | Error::MultisigNotFound
        | Error::KeyExists
        | Error::KeyNotFound
        | Error::ApiTokenTooShort
        | Error::ApiTokenTooLong
        | Error::AlreadyRunning
        | Error::DataDirMissing(_) => StatusCode::BAD_REQUEST,
        // 400 — password / decrypt failures default to "bad request"
        // (matches Go at `wallet.go`/`sqlite.go` callers that hand
        // these to `errorResponse(... http.StatusBadRequest, err)`).
        // Init-wallet's caller overrides this to 401 explicitly.
        Error::Decrypt | Error::TypeMismatch | Error::DeriveKey | Error::Tampering => {
            StatusCode::BAD_REQUEST
        }
        // 500 — genuine internal failures.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Human-readable message body.  We use `err.to_string()` directly —
/// every variant's `#[error("...")]` was chosen to match Go's
/// `err.Error()` string when surfaced over the API.  See the variant
/// docstrings in [`crate::error`] for the per-error mapping.
pub fn error_message(err: &Error) -> String {
    err.to_string()
}

/// Build the standard error response: `{"error":true,"message":...}`
/// with the supplied status code.  Mirrors `errorResponse` in Go.
fn err_response(status: StatusCode, message: impl Into<String>) -> Response {
    let body = APIV1ResponseEnvelope {
        error: true,
        message: message.into(),
    };
    // Use Json so the response carries `application/json`.  The
    // body shape matches Go exactly (a bare envelope, no nested
    // object).
    (status, Json(body)).into_response()
}

/// Decode an incoming JSON body, returning Go's `errCouldNotDecode`
/// 400 on parse failure.  Used by every POST handler — Go has the
/// same boilerplate (`json.NewDecoder(r.Body).Decode(&req)` →
/// `errorResponse(w, StatusBadRequest, errCouldNotDecode)`).
async fn decode_body<T>(req: axum::extract::Request) -> Result<T, Response>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => return Err(err_response(StatusCode::BAD_REQUEST, ERR_COULD_NOT_DECODE)),
    };
    // Go's `json.NewDecoder(r.Body).Decode(&req)` returns `io.EOF`
    // on an empty body, which the v1 handlers translate to
    // `errCouldNotDecode` → 400.  We mirror that — refusing to
    // silently accept a default-valued request lets clients catch
    // missing-content-type / unsent-body bugs early.
    if bytes.is_empty() {
        return Err(err_response(StatusCode::BAD_REQUEST, ERR_COULD_NOT_DECODE));
    }
    match serde_json::from_slice::<T>(&bytes) {
        Ok(req) => Ok(req),
        Err(_) => Err(err_response(StatusCode::BAD_REQUEST, ERR_COULD_NOT_DECODE)),
    }
}

/// `errCouldNotDecode = "could not decode request body"`
/// (`api/v1/errors.go:23`).
const ERR_COULD_NOT_DECODE: &str = "could not decode request body";

/// `errCouldNotDecodeAddress = "could not decode address"`
/// (`api/v1/errors.go:24`).  Returned for any unparseable
/// base32-with-checksum address string.
const ERR_COULD_NOT_DECODE_ADDRESS: &str = "could not decode address";

/// Parse an Algorand checksum-address string into its 32-byte form.
/// On any parse error, returns Go's `errCouldNotDecodeAddress` 400
/// envelope (mirrors `basics.UnmarshalChecksumAddress` failures at
/// the v1 handler call sites — handlers.go:615, :724).
// `Response` is a fat enum, but it's the natural error type here —
// every caller propagates it to the client.  Boxing it would just
// add an allocation on the error path without changing the shape
// we hand back to axum.
#[allow(clippy::result_large_err)]
fn parse_address(s: &str) -> Result<[u8; 32], Response> {
    Address::from_algorand_string(s)
        .map(|a| a.0)
        .map_err(|_| err_response(StatusCode::BAD_REQUEST, ERR_COULD_NOT_DECODE_ADDRESS))
}

/// Encode a 32-byte public key as an Algorand checksum-address
/// string. Mirrors Go's `basics.Address(...).GetUserAddress()`.
fn encode_address(pk: &[u8; 32]) -> String {
    Address(*pk).to_algorand_string()
}

// ---------------------------------------------------------------- helpers

fn api_wallet_from_metadata(m: &WalletMetadata) -> APIV1Wallet {
    APIV1Wallet {
        id: String::from_utf8_lossy(&m.id).into_owned(),
        name: String::from_utf8_lossy(&m.name).into_owned(),
        driver_name: m.driver_name.clone(),
        driver_version: m.driver_version,
        supports_mnemonic_ux: SQLITE_SUPPORTS_MNEMONIC_UX,
        supported_transactions: SQLITE_SUPPORTED_TXS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    }
}

/// Generate a fresh 32-char lowercase-hex wallet ID.  Matches
/// `wallet.GenerateWalletID` (`daemon/kmd/wallet/wallet.go:75`).
fn generate_wallet_id() -> Result<String, Error> {
    use rand::RngCore;
    let mut bytes = [0u8; WALLET_ID_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| Error::RandBytes)?;
    let mut s = String::with_capacity(WALLET_ID_BYTES * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(s)
}

/// Run a synchronous closure on a blocking worker.  SQLite + scrypt
/// are CPU-bound and would otherwise stall the tokio runtime if
/// invoked directly from a handler.
async fn blocking<T, F>(f: F) -> Result<T, Response>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => {
            let status = status_for_error(&e);
            Err(err_response(status, error_message(&e)))
        }
        Err(join_err) => Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("worker panicked: {join_err}"),
        )),
    }
}

/// Like [`blocking`] but with a caller-supplied status code override
/// (used by init-wallet, which converts a `Decrypt` error from a
/// password check into 401 instead of the default 400).
async fn blocking_with_status<T, F>(f: F, error_status: StatusCode) -> Result<T, Response>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(err_response(error_status, error_message(&e))),
        Err(join_err) => Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("worker panicked: {join_err}"),
        )),
    }
}

fn ok_json<T: serde::Serialize>(body: T) -> Response {
    let json = serde_json::to_vec(&body).expect("response always serializes");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response()
}

// ---------------------------------------------------------------- handlers

/// `GET /v1/wallets` — list all wallet metadatas.  Mirrors
/// `getWalletsHandler` (handlers.go:88).
async fn get_wallets(State(state): State<AppState>) -> Response {
    let driver = state.wallet_driver.clone();
    let metadatas = match blocking(move || driver.list_wallet_metadatas()).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let wallets = metadatas.iter().map(api_wallet_from_metadata).collect();
    ok_json(APIV1GETWalletsResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallets,
    })
}

/// `POST /v1/wallet` — create wallet.  Mirrors `postWalletHandler`
/// (handlers.go:128).
async fn post_wallet(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTWalletRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    // We support exactly the SQLite driver — any other name (or an
    // empty name) is rejected with Go's `"unknown wallet driver"`
    // (`daemon/kmd/wallet/driver/driver.go:62`).  Go's registry
    // lookup `walletDrivers[req.WalletDriverName]` returns nil for
    // the empty string too, so a body like `{"wallet_password":"x"}`
    // must fail rather than silently default to SQLite.
    if req.wallet_driver_name != SQLITE_WALLET_DRIVER_NAME {
        return err_response(
            StatusCode::BAD_REQUEST,
            error_message(&Error::UnknownWalletDriver),
        );
    }

    // Generate the wallet ID (Go does this in `postWalletHandler` at
    // handlers.go:162) — we keep that order so a name collision
    // still aborts before any DB writes happen.
    let wallet_id = match generate_wallet_id() {
        Ok(s) => s,
        Err(e) => return err_response(status_for_error(&e), error_message(&e)),
    };

    // Blank name → use the ID as name (handlers.go:169).
    let wallet_name = if req.wallet_name.is_empty() {
        wallet_id.clone()
    } else {
        req.wallet_name.clone()
    };

    let driver = state.wallet_driver.clone();
    let id_bytes = wallet_id.as_bytes().to_vec();
    let name_bytes = wallet_name.as_bytes().to_vec();
    let password = req.wallet_password.clone();
    let mdk = req.master_derivation_key;

    let metadata = match blocking(move || {
        // Treat all-zero MDK as "generate one" (`sqlite.go:451`).
        let mdk_opt = if mdk == [0u8; 32] { None } else { Some(mdk) };
        driver.create_wallet(&name_bytes, &id_bytes, password.as_bytes(), mdk_opt)?;
        let wallet = driver.fetch_wallet(&id_bytes)?;
        wallet.metadata()
    })
    .await
    {
        Ok(m) => m,
        Err(r) => return r,
    };

    ok_json(APIV1POSTWalletResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallet: api_wallet_from_metadata(&metadata),
    })
}

/// `POST /v1/wallet/init` — unlock a wallet, mint a handle token.
/// Mirrors `postWalletInitHandler` (handlers.go:205).
async fn post_wallet_init(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTWalletInitRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let driver = state.wallet_driver.clone();
    let session_manager = state.session_manager.clone();
    let wallet_id = req.wallet_id.into_bytes();
    let password = req.wallet_password;

    // Fetch + unlock + register handle in one blocking call so we
    // don't ping-pong between the runtime and the worker per step.
    // The error mapping here matches Go: `FetchWalletByID` failures
    // are 400 (handlers.go:238); password/init failures are 401
    // (handlers.go:245).
    //
    // We can't use the default mapping for both, so we run them as
    // two sequential blocking calls, the second wrapping the
    // "unlock + init handle" pair under a fixed 401 status.
    let driver_clone = driver.clone();
    let id_for_fetch = wallet_id.clone();
    let mut wallet = match blocking(move || driver_clone.fetch_wallet(&id_for_fetch)).await {
        Ok(w) => w,
        Err(r) => return r,
    };

    let token = match blocking_with_status(
        move || {
            wallet.init(password.as_bytes())?;
            session_manager.init_wallet_handle(wallet)
        },
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(t) => t,
        Err(r) => return r,
    };

    ok_json(APIV1POSTWalletInitResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallet_handle_token: token,
    })
}

/// `POST /v1/wallet/release` — invalidate a handle token.  Mirrors
/// `postWalletReleaseHandler` (handlers.go:368).
async fn post_wallet_release(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let req: APIV1POSTWalletReleaseRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    match blocking_with_status(
        move || session_manager.release_wallet_handle(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(()) => ok_json(APIV1POSTWalletReleaseResponse::default()),
        Err(r) => r,
    }
}

/// `POST /v1/wallet/renew` — bump a handle's expiry.  Mirrors
/// `postWalletRenewHandler` (handlers.go:409).
async fn post_wallet_renew(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTWalletRenewRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.renew_wallet_handle(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let metadata = match blocking(move || handle.wallet.metadata()).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    ok_json(APIV1POSTWalletRenewResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallet_handle: APIV1WalletHandle {
            wallet: api_wallet_from_metadata(&metadata),
            expires_seconds: handle.expires_seconds,
        },
    })
}

/// `POST /v1/wallet/rename` — rename a wallet.  Mirrors
/// `postWalletRenameHandler` (handlers.go:462).
async fn post_wallet_rename(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let req: APIV1POSTWalletRenameRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let driver = state.wallet_driver.clone();
    let id = req.wallet_id.into_bytes();
    let new_name = req.new_wallet_name.into_bytes();
    let password = req.wallet_password;

    let metadata = match blocking(move || {
        driver.rename_wallet(&id, &new_name, password.as_bytes())?;
        let wallet = driver.fetch_wallet(&id)?;
        wallet.metadata()
    })
    .await
    {
        Ok(m) => m,
        Err(r) => return r,
    };

    ok_json(APIV1POSTWalletRenameResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallet: api_wallet_from_metadata(&metadata),
    })
}

/// `POST /v1/wallet/info` — wallet metadata + remaining handle
/// lifetime.  Mirrors `postWalletInfoHandler` (handlers.go:259).
async fn post_wallet_info(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTWalletInfoRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let metadata = match blocking(move || handle.wallet.metadata()).await {
        Ok(m) => m,
        Err(r) => return r,
    };

    ok_json(APIV1POSTWalletInfoResponse {
        envelope: APIV1ResponseEnvelope::default(),
        wallet_handle: APIV1WalletHandle {
            wallet: api_wallet_from_metadata(&metadata),
            expires_seconds: handle.expires_seconds,
        },
    })
}

/// `POST /v1/master-key/export` — export the master derivation key
/// after re-verifying the wallet password.  Mirrors
/// `postMasterKeyExportHandler` (handlers.go:314).
async fn post_master_key_export(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> Response {
    let req: APIV1POSTMasterKeyExportRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let password = req.wallet_password;
    // Go reports wrong-password here as 400 (handlers.go:354), NOT 401
    // — only the wallet-init / handle-token errors are 401.
    let mdk = match blocking(move || {
        handle
            .wallet
            .export_master_derivation_key(password.as_bytes())
    })
    .await
    {
        Ok(k) => k,
        Err(r) => return r,
    };

    ok_json(APIV1POSTMasterKeyExportResponse {
        envelope: APIV1ResponseEnvelope::default(),
        master_derivation_key: mdk,
    })
}

// ---------------------------------------------------------------- Key handlers (B6)

/// `POST /v1/key/list` — list addresses in the unlocked wallet.
/// Mirrors `postKeyListHandler` (handlers.go:750).
async fn post_key_list(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTKeyListRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let addrs = match blocking(move || handle.wallet.list_keys()).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let addresses = addrs.iter().map(encode_address).collect();

    ok_json(APIV1POSTKeyListResponse {
        envelope: APIV1ResponseEnvelope::default(),
        addresses,
    })
}

/// `POST /v1/key/import` — import an externally-generated key.
/// Mirrors `postKeyImportHandler` (handlers.go:533).
async fn post_key_import(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTKeyImportRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let secret = req.private_key;
    let addr = match blocking(move || handle.wallet.import_key(&secret)).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    ok_json(APIV1POSTKeyImportResponse {
        envelope: APIV1ResponseEnvelope::default(),
        address: encode_address(&addr),
    })
}

/// `POST /v1/key/export` — export the 64-byte expanded secret key
/// for a single address, after a password re-verify.  Mirrors
/// `postKeyExportHandler` (handlers.go:586).
async fn post_key_export(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTKeyExportRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    // Parse the address before touching the session — Go does the
    // same order at handlers.go:613, so a bad address surfaces as
    // 400 even when the handle token would also have been rejected.
    let addr = match parse_address(&req.address) {
        Ok(a) => a,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let password = req.wallet_password;
    let sk = match blocking(move || handle.wallet.export_key(&addr, password.as_bytes())).await {
        Ok(k) => k,
        Err(r) => return r,
    };

    ok_json(APIV1POSTKeyExportResponse {
        envelope: APIV1ResponseEnvelope::default(),
        private_key: sk,
    })
}

/// `POST /v1/key` — generate a new key from the wallet's MDK.
/// Mirrors `postKeyHandler` (handlers.go:643).
async fn post_key(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1POSTKeyRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };
    // `display_mnemonic` is accepted on the wire for parity but the
    // SQLite driver rejects mnemonic-UX requests (sqlite.go:850).
    // Our `Wallet::generate_key` doesn't take a `display_mnemonic`
    // parameter — it always behaves as `display_mnemonic == false`
    // for the SQLite driver, which is what Go does.

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    // Go reports any error from GenerateKey as 500 (handlers.go:681).
    // We use the default mapping so e.g. WalletNotInitialized still
    // surfaces as 500 (an "internal" condition — the handle token
    // was valid but the wallet's unlocked state is missing).
    let addr = match blocking_with_status(
        move || handle.wallet.generate_key(),
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };

    ok_json(APIV1POSTKeyResponse {
        envelope: APIV1ResponseEnvelope::default(),
        address: encode_address(&addr),
    })
}

/// `DELETE /v1/key` — remove a key by address after a password
/// re-verify.  Mirrors `deleteKeyHandler` (handlers.go:695).
async fn delete_key(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    let req: APIV1DELETEKeyRequest = match decode_body(req).await {
        Ok(r) => r,
        Err(r) => return r,
    };

    let addr = match parse_address(&req.address) {
        Ok(a) => a,
        Err(r) => return r,
    };

    let session_manager = state.session_manager.clone();
    let token = req.wallet_handle_token;
    let handle = match blocking_with_status(
        move || session_manager.auth_with_token(&token),
        StatusCode::UNAUTHORIZED,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    let password = req.wallet_password;
    match blocking(move || handle.wallet.delete_key(&addr, password.as_bytes())).await {
        Ok(()) => ok_json(APIV1DELETEKeyResponse::default()),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScryptParams, DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_P, DEFAULT_SCRYPT_R};
    use crate::wallet::WalletDriverConfig;
    use serde_json::json;
    use std::time::Duration;
    use tempfile::TempDir;
    use tower::ServiceExt; // for `oneshot`

    /// Build a Router from a fresh state + temp data dir.  Returns
    /// the router and the TempDir guard so the wallets dir lives as
    /// long as the test.
    fn make_router() -> (Router, TempDir) {
        // Use insecure scrypt params for fast tests — same shape Go
        // uses in its unit tests.
        let tmp = TempDir::new().unwrap();
        let driver = WalletDriver::new(WalletDriverConfig {
            wallets_dir: tmp.path().to_path_buf(),
            scrypt_params: ScryptParams {
                scrypt_n: 2,
                scrypt_r: 1,
                scrypt_p: 1,
            },
            allow_unsafe_scrypt: true,
        })
        .unwrap();
        let state = AppState {
            session_manager: Arc::new(SessionManager::new(Duration::from_secs(60))),
            wallet_driver: Arc::new(driver),
        };
        (router(state), tmp)
    }

    async fn post(
        router: &Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn get(router: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    #[tokio::test]
    async fn empty_wallets_list_returns_empty_array_or_omitted() {
        let (router, _tmp) = make_router();
        let (status, body) = get(&router, "/wallets").await;
        assert_eq!(status, 200);
        // Go's `_struct codec:",omitempty,omitemptyarray"` omits an
        // empty `wallets` field; both `{}` and `{"wallets":[]}` are
        // valid wire shapes.  Our serializer matches Go.
        assert!(body.get("wallets").is_none() || body["wallets"].as_array().unwrap().is_empty());
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn full_happy_path_create_init_info_export_release() {
        let (router, _tmp) = make_router();
        let pwd = "hunter2";

        // 1. Create wallet
        let (s, body) = post(
            &router,
            "/wallet",
            json!({"wallet_name": "alpha", "wallet_driver_name": "sqlite", "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "create wallet: {body}");
        let wallet_id = body["wallet"]["id"].as_str().unwrap().to_string();
        assert_eq!(body["wallet"]["name"], "alpha");
        assert_eq!(body["wallet"]["driver_name"], "sqlite");
        assert_eq!(body["wallet"]["mnemonic_ux"], false);

        // 2. Init handle
        let (s, body) = post(
            &router,
            "/wallet/init",
            json!({"wallet_id": wallet_id, "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "init: {body}");
        let token = body["wallet_handle_token"].as_str().unwrap().to_string();

        // 3. Wallet info
        let (s, body) = post(
            &router,
            "/wallet/info",
            json!({"wallet_handle_token": token}),
        )
        .await;
        assert_eq!(s, 200, "info: {body}");
        assert_eq!(body["wallet_handle"]["wallet"]["id"], wallet_id);
        let expires = body["wallet_handle"]["expires_seconds"].as_i64().unwrap();
        assert!(expires > 0 && expires <= 60);

        // 4. Renew bumps expiry — sleep briefly, then ensure expires_seconds is at the cap again.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (s, body) = post(
            &router,
            "/wallet/renew",
            json!({"wallet_handle_token": token}),
        )
        .await;
        assert_eq!(s, 200, "renew: {body}");
        let expires_after_renew = body["wallet_handle"]["expires_seconds"].as_i64().unwrap();
        assert!(
            expires_after_renew >= expires - 1,
            "renew should bump expiry back to the cap; got {expires_after_renew} after pre-renew {expires}"
        );

        // 5. Export MDK
        let (s, body) = post(
            &router,
            "/master-key/export",
            json!({"wallet_handle_token": token, "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "mdk export: {body}");
        assert!(body["master_derivation_key"].is_string());

        // 6. List wallets shows the new wallet.
        let (s, body) = get(&router, "/wallets").await;
        assert_eq!(s, 200);
        let wallets = body["wallets"].as_array().unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0]["id"], wallet_id);

        // 7. Release token.
        let (s, body) = post(
            &router,
            "/wallet/release",
            json!({"wallet_handle_token": token}),
        )
        .await;
        assert_eq!(s, 200, "release: {body}");

        // 8. Subsequent info on the released token → 401.
        let (s, body) = post(
            &router,
            "/wallet/info",
            json!({"wallet_handle_token": token}),
        )
        .await;
        assert_eq!(s, 401, "info after release: {body}");
        assert_eq!(body["error"], true);
    }

    #[tokio::test]
    async fn wrong_password_on_init_returns_401() {
        let (router, _tmp) = make_router();
        let (s, body) = post(
            &router,
            "/wallet",
            json!({"wallet_name": "alpha", "wallet_driver_name": "sqlite", "wallet_password": "right"}),
        )
        .await;
        assert_eq!(s, 200, "create: {body}");
        let id = body["wallet"]["id"].as_str().unwrap().to_string();

        let (s, body) = post(
            &router,
            "/wallet/init",
            json!({"wallet_id": id, "wallet_password": "WRONG"}),
        )
        .await;
        assert_eq!(s, 401);
        assert_eq!(body["error"], true);
        // Go's error text for wrong password is errDecrypt → "failed
        // to decrypt blob" in our port (matches the variant docstring).
        assert!(
            body["message"].as_str().unwrap().contains("decrypt"),
            "message: {}",
            body["message"]
        );
    }

    #[tokio::test]
    async fn unknown_wallet_id_on_init_returns_400() {
        let (router, _tmp) = make_router();
        let (s, body) = post(
            &router,
            "/wallet/init",
            json!({"wallet_id": "deadbeef", "wallet_password": "x"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("wallet not found"));
    }

    #[tokio::test]
    async fn rename_with_correct_password_succeeds() {
        let (router, _tmp) = make_router();
        let pwd = "secret";
        let (_, body) = post(
            &router,
            "/wallet",
            json!({"wallet_name": "old", "wallet_driver_name": "sqlite", "wallet_password": pwd}),
        )
        .await;
        let id = body["wallet"]["id"].as_str().unwrap().to_string();

        let (s, body) = post(
            &router,
            "/wallet/rename",
            json!({"wallet_id": id, "wallet_password": pwd, "wallet_name": "new"}),
        )
        .await;
        assert_eq!(s, 200, "rename: {body}");
        assert_eq!(body["wallet"]["name"], "new");
    }

    #[tokio::test]
    async fn rename_with_wrong_password_returns_400() {
        let (router, _tmp) = make_router();
        let (_, body) = post(
            &router,
            "/wallet",
            json!({"wallet_name": "old", "wallet_driver_name": "sqlite", "wallet_password": "right"}),
        )
        .await;
        let id = body["wallet"]["id"].as_str().unwrap().to_string();

        let (s, body) = post(
            &router,
            "/wallet/rename",
            json!({"wallet_id": id, "wallet_password": "WRONG", "wallet_name": "new"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
    }

    #[tokio::test]
    async fn master_key_export_wrong_password_returns_400_not_401() {
        let (router, _tmp) = make_router();
        let (_, body) = post(
            &router,
            "/wallet",
            json!({"wallet_driver_name": "sqlite", "wallet_password": "right"}),
        )
        .await;
        let id = body["wallet"]["id"].as_str().unwrap().to_string();
        let (_, body) = post(
            &router,
            "/wallet/init",
            json!({"wallet_id": id, "wallet_password": "right"}),
        )
        .await;
        let token = body["wallet_handle_token"].as_str().unwrap().to_string();

        // Wrong password on master-key-export — Go returns 400 here
        // (handlers.go:354), not 401.  401 is reserved for the
        // handle-token auth step.
        let (s, body) = post(
            &router,
            "/master-key/export",
            json!({"wallet_handle_token": token, "wallet_password": "WRONG"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
    }

    #[tokio::test]
    async fn create_wallet_with_unknown_driver_returns_400() {
        let (router, _tmp) = make_router();
        let (s, body) = post(
            &router,
            "/wallet",
            json!({"wallet_driver_name": "ledger", "wallet_password": "x"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
    }

    #[tokio::test]
    async fn empty_post_body_returns_could_not_decode() {
        // Regression for Codex PR #356 round 1 (P1):
        // Go's `json.Decode(r.Body)` returns io.EOF on an empty body
        // — the v1 handlers map that to errCouldNotDecode → 400.
        // We must NOT silently accept the default request shape.
        let (router, _tmp) = make_router();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/wallet")
            .header("content-type", "application/json")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 400);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], true);
        assert_eq!(v["message"], ERR_COULD_NOT_DECODE);
    }

    #[tokio::test]
    async fn create_wallet_missing_driver_name_returns_unknown_driver_400() {
        // Regression for Codex PR #356 round 1 (P1):
        // Go's `FetchWalletDriver("")` returns "unknown wallet driver"
        // because the registry doesn't have an empty-string key.  A
        // body like `{"wallet_password":"x"}` (no driver name) must
        // fail rather than silently default to SQLite.
        let (router, _tmp) = make_router();
        let (s, body) = post(&router, "/wallet", json!({"wallet_password": "x"})).await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
        assert_eq!(body["message"], "unknown wallet driver");
    }

    #[tokio::test]
    async fn unparseable_body_returns_could_not_decode() {
        let (router, _tmp) = make_router();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/wallet")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("not-json"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 400);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], true);
        assert_eq!(v["message"], ERR_COULD_NOT_DECODE);
    }

    // ---- B6 key handler tests ----

    /// Helper: create a wallet, init a handle, return (router, token).
    async fn make_unlocked(pwd: &str) -> (Router, tempfile::TempDir, String) {
        let (router, tmp) = make_router();
        let (s, body) = post(
            &router,
            "/wallet",
            json!({"wallet_name": "w", "wallet_driver_name": "sqlite", "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "create: {body}");
        let id = body["wallet"]["id"].as_str().unwrap().to_string();
        let (s, body) = post(
            &router,
            "/wallet/init",
            json!({"wallet_id": id, "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "init: {body}");
        let token = body["wallet_handle_token"].as_str().unwrap().to_string();
        (router, tmp, token)
    }

    #[tokio::test]
    async fn key_full_lifecycle_generate_list_export_delete() {
        let pwd = "pw";
        let (router, _tmp, token) = make_unlocked(pwd).await;

        // Generate a key.
        let (s, body) = post(&router, "/key", json!({"wallet_handle_token": token})).await;
        assert_eq!(s, 200, "generate: {body}");
        let addr = body["address"].as_str().unwrap().to_string();
        assert_eq!(addr.len(), 58, "Algorand addresses are 58 chars");

        // List shows the new address.
        let (s, body) = post(&router, "/key/list", json!({"wallet_handle_token": token})).await;
        assert_eq!(s, 200, "list: {body}");
        let addresses: Vec<String> = body["addresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(
            addresses.contains(&addr),
            "list should contain {addr}: {addresses:?}"
        );

        // Export gets back the 64-byte secret key (base64).
        let (s, body) = post(
            &router,
            "/key/export",
            json!({"wallet_handle_token": token, "address": addr, "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "export: {body}");
        let sk_b64 = body["private_key"].as_str().unwrap();
        // 64 bytes -> 88 chars base64 with padding.
        assert_eq!(
            sk_b64.len(),
            88,
            "expanded SK is 64 bytes -> 88 chars base64"
        );

        // Delete with the right password.
        let (s, body) = post_method(
            &router,
            "DELETE",
            "/key",
            json!({"wallet_handle_token": token, "address": addr, "wallet_password": pwd}),
        )
        .await;
        assert_eq!(s, 200, "delete: {body}");

        // List now empty.
        let (s, body) = post(&router, "/key/list", json!({"wallet_handle_token": token})).await;
        assert_eq!(s, 200, "post-delete list: {body}");
        assert!(
            body.get("addresses").is_none() || body["addresses"].as_array().unwrap().is_empty(),
            "list should be empty after delete: {body}"
        );
    }

    #[tokio::test]
    async fn key_export_wrong_password_returns_400() {
        let pwd = "right";
        let (router, _tmp, token) = make_unlocked(pwd).await;
        let (_, body) = post(&router, "/key", json!({"wallet_handle_token": token})).await;
        let addr = body["address"].as_str().unwrap().to_string();

        let (s, body) = post(
            &router,
            "/key/export",
            json!({"wallet_handle_token": token, "address": addr, "wallet_password": "WRONG"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["error"], true);
    }

    #[tokio::test]
    async fn key_export_bad_address_returns_could_not_decode_address() {
        let (router, _tmp, token) = make_unlocked("pw").await;
        let (s, body) = post(
            &router,
            "/key/export",
            json!({"wallet_handle_token": token, "address": "NOT-AN-ADDRESS", "wallet_password": "pw"}),
        )
        .await;
        assert_eq!(s, 400);
        assert_eq!(body["message"], "could not decode address");
    }

    #[tokio::test]
    async fn key_import_round_trips_through_export() {
        let pwd = "pw";
        let (router, _tmp, token) = make_unlocked(pwd).await;

        // Build a known seed + expanded SK.
        let seed = [0x11u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let mut expanded = [0u8; 64];
        expanded[..32].copy_from_slice(&seed);
        expanded[32..].copy_from_slice(&pk);

        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let sk_b64 = B64.encode(expanded);

        let (s, body) = post(
            &router,
            "/key/import",
            json!({"wallet_handle_token": token, "private_key": sk_b64}),
        )
        .await;
        assert_eq!(s, 200, "import: {body}");
        let addr = body["address"].as_str().unwrap().to_string();

        // Re-import should fail with "key already exists" → 400.
        let (s, body) = post(
            &router,
            "/key/import",
            json!({"wallet_handle_token": token, "private_key": sk_b64}),
        )
        .await;
        assert_eq!(s, 400, "double import: {body}");

        // Export gets back the same expanded SK.
        let (_, body) = post(
            &router,
            "/key/export",
            json!({"wallet_handle_token": token, "address": addr, "wallet_password": pwd}),
        )
        .await;
        let exported_b64 = body["private_key"].as_str().unwrap();
        let exported = B64.decode(exported_b64).unwrap();
        assert_eq!(exported, expanded);
    }

    #[tokio::test]
    async fn key_routes_reject_invalid_token() {
        let (router, _tmp) = make_router();
        // Token-only routes — auth runs before any other validation.
        for path in ["/key/list", "/key/import", "/key"] {
            let (s, body) = post(&router, path, json!({"wallet_handle_token": "bogus"})).await;
            assert_eq!(s, 401, "{path}: {body}");
            assert_eq!(body["error"], true);
        }
        // /key/export + DELETE /key parse the address BEFORE the
        // token check (matching Go handlers.go:613 / :722), so pass
        // a syntactically valid address; the token check then fires.
        let valid_addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-FQA"; // zero-address w/ checksum
                                                                                     // Build a real zero-address string via the codec so the
                                                                                     // test doesn't depend on our hand-typed value matching the
                                                                                     // checksum algorithm exactly.
        let zero_addr = Address([0u8; 32]).to_algorand_string();
        let _ = valid_addr;
        let (s, body) = post(
            &router,
            "/key/export",
            json!({
                "wallet_handle_token": "bogus",
                "address": zero_addr,
                "wallet_password": "x",
            }),
        )
        .await;
        assert_eq!(s, 401, "/key/export: {body}");
        let (s, body) = post_method(
            &router,
            "DELETE",
            "/key",
            json!({
                "wallet_handle_token": "bogus",
                "address": zero_addr,
                "wallet_password": "x",
            }),
        )
        .await;
        assert_eq!(s, 401, "DELETE /key: {body}");
    }

    /// Helper that lets us post a body with a non-POST method (used
    /// for DELETE /v1/key, which carries its body the same way Go's
    /// gorilla/mux handler does).
    async fn post_method(
        router: &Router,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    /// Sanity check we're using insecure scrypt only via
    /// `allow_unsafe_scrypt`; production defaults are still gated.
    #[test]
    fn production_scrypt_defaults_are_above_floor() {
        assert!(DEFAULT_SCRYPT_N as u32 >= crate::crypto::MIN_SCRYPT_N);
        assert!(DEFAULT_SCRYPT_R as u32 >= crate::crypto::MIN_SCRYPT_R);
        assert!(DEFAULT_SCRYPT_P as u32 >= crate::crypto::MIN_SCRYPT_P);
    }
}
