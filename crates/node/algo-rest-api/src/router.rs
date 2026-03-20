//! Router construction for the Algorand REST API.
//!
//! Builds the axum `Router` with all endpoint handlers, separating
//! public (no-auth) routes from authenticated routes that require
//! API token validation.

use std::sync::Arc;

use axum::middleware;
use axum::routing::get;
use axum::Router;

use crate::auth;
use crate::handlers;
use crate::node::NodeInterface;

/// Token configuration for the API router.
///
/// Separates public (algod.token) and admin (algod.admin.token) tiers,
/// matching go-algorand's dual-token authentication model.
#[derive(Debug, Clone)]
pub struct TokenConfig {
    /// The public API token (from `algod.token`).
    /// Required for standard v2 endpoints.
    pub api_token: String,

    /// The admin API token (from `algod.admin.token`).
    /// Required for admin-only endpoints (shutdown, catchup management, etc.).
    pub admin_token: String,
}

/// Build the complete API router.
///
/// The router is split into three layers:
/// - **Public routes**: `/health`, `/ready`, `/versions`, `/genesis`,
///   `/swagger.json` -- these do not require API token authentication.
/// - **Authenticated routes**: `/v2/...` endpoints that require a valid
///   public API token (`algod.token`) in `X-Algo-API-Token` header or
///   `Authorization: Bearer <token>`.
/// - **Admin routes**: endpoints that require the admin token
///   (`algod.admin.token`). Reserved for future admin endpoints.
pub fn build_router<N: NodeInterface>(node: Arc<N>, tokens: TokenConfig) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .route("/health", get(handlers::health::<N>))
        .route("/ready", get(handlers::ready::<N>))
        .route("/versions", get(handlers::versions::<N>))
        .route("/genesis", get(handlers::genesis::<N>))
        .route("/swagger.json", get(handlers::swagger_json));

    // Authenticated routes (public API token required)
    let authenticated = Router::new()
        .route("/v2/status", get(handlers::get_status::<N>))
        .route(
            "/v2/status/wait-for-block-after/:round",
            get(handlers::wait_for_block::<N>),
        )
        .route(
            "/v2/transactions/params",
            get(handlers::transaction_params::<N>),
        )
        .route(
            "/v2/accounts/:address",
            get(handlers::account_information::<N>),
        )
        .route(
            "/v2/accounts/:address/assets/:asset-id",
            get(handlers::account_asset_information::<N>),
        )
        .route(
            "/v2/accounts/:address/applications/:application-id",
            get(handlers::account_application_information::<N>),
        )
        .route(
            "/v2/applications/:application-id",
            get(handlers::get_application_by_id::<N>),
        )
        .route("/v2/assets/:asset-id", get(handlers::get_asset_by_id::<N>))
        .route(
            "/v2/applications/:application-id/box",
            get(handlers::get_application_box_by_name::<N>),
        )
        .route(
            "/v2/applications/:application-id/boxes",
            get(handlers::get_application_boxes::<N>),
        )
        .route("/v2/blocks/:round", get(handlers::get_block::<N>))
        .route("/v2/blocks/:round/hash", get(handlers::get_block_hash::<N>))
        .route(
            "/v2/blocks/:round/txids",
            get(handlers::get_block_txids::<N>),
        )
        .route("/v2/blocks/:round/logs", get(handlers::get_block_logs::<N>))
        .route(
            "/v2/blocks/:round/transactions/:txid/proof",
            get(handlers::get_transaction_proof::<N>),
        )
        .route(
            "/v2/blocks/:round/lightheader/proof",
            get(handlers::get_light_block_header_proof::<N>),
        )
        .layer(middleware::from_fn_with_state(
            tokens.api_token.clone(),
            auth::require_token,
        ));

    // Admin routes (admin API token required)
    // Future admin endpoints will be added here.
    let admin = Router::new().layer(middleware::from_fn_with_state(
        tokens.admin_token.clone(),
        auth::require_token,
    ));

    // Merge all route groups with shared node state
    public.merge(authenticated).merge(admin).with_state(node)
}
