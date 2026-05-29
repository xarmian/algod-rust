//! Router construction for the Algorand REST API.
//!
//! Builds the axum `Router` with all endpoint handlers, separating
//! public (no-auth) routes from authenticated routes that require
//! API token validation.

use std::sync::Arc;

use axum::middleware;
use axum::routing::{get, post};
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

    /// Whether the Experimental API is enabled.
    ///
    /// When true, experimental endpoints are registered in the router.
    /// Mirrors go-algorand's `Config().EnableExperimentalAPI`.
    pub enable_experimental_api: bool,
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
/// - **Data routes**: the follower-mode `/v2/ledger/sync` endpoints, registered
///   only when the node is in follower mode and guarded by the public API token
///   (matching go-algorand's `data.RegisterHandlers` under `EnableFollowMode`).
pub fn build_router<N: NodeInterface>(node: Arc<N>, tokens: TokenConfig) -> Router {
    // The data API (`/v2/ledger/sync`) is only exposed in follower mode, matching
    // go-algorand's conditional `data.RegisterHandlers` under `EnableFollowMode`.
    let follower_mode = node.is_follower_mode();

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
        .route("/v2/transactions", post(handlers::raw_transaction::<N>))
        .route(
            "/v2/transactions/simulate",
            post(handlers::simulate_transaction::<N>),
        )
        .route(
            "/v2/transactions/pending",
            get(handlers::get_pending_transactions::<N>),
        )
        .route(
            "/v2/transactions/pending/:txid",
            get(handlers::pending_transaction_information::<N>),
        )
        .route(
            "/v2/accounts/:address/transactions/pending",
            get(handlers::get_pending_transactions_by_address::<N>),
        )
        .route(
            "/v2/blocks/:round/transactions/:txid/proof",
            get(handlers::get_transaction_proof::<N>),
        )
        .route(
            "/v2/blocks/:round/lightheader/proof",
            get(handlers::get_light_block_header_proof::<N>),
        )
        .route("/v2/ledger/supply", get(handlers::get_supply::<N>))
        .route(
            "/v2/stateproofs/:round",
            get(handlers::get_state_proof::<N>),
        )
        .route("/v2/deltas/:round", get(handlers::get_state_delta::<N>))
        .route(
            "/v2/deltas/txn/group/:id",
            get(handlers::get_txn_group_delta::<N>),
        )
        .route(
            "/v2/deltas/:round/txn/group",
            get(handlers::get_txn_group_deltas_for_round::<N>),
        )
        .route("/v2/teal/compile", post(handlers::teal_compile::<N>))
        .route(
            "/v2/teal/disassemble",
            post(handlers::teal_disassemble::<N>),
        )
        .route("/v2/teal/dryrun", post(handlers::teal_dryrun::<N>))
        .route(
            "/v2/devmode/blocks/offset",
            get(handlers::get_block_timestamp_offset::<N>),
        )
        .route(
            "/v2/devmode/blocks/offset/:offset",
            post(handlers::set_block_timestamp_offset::<N>),
        )
        .layer(middleware::from_fn_with_state(
            tokens.api_token.clone(),
            auth::require_token,
        ));

    // Admin routes (admin API token required)
    let admin = Router::new()
        .route(
            "/v2/catchup/:catchpoint",
            post(handlers::start_catchup::<N>).delete(handlers::abort_catchup::<N>),
        )
        .route("/v2/shutdown", post(handlers::shutdown_node::<N>))
        .route(
            "/debug/settings/pprof",
            get(handlers::get_debug_settings_prof::<N>).put(handlers::put_debug_settings_prof::<N>),
        )
        .route("/debug/settings/config", get(handlers::get_config::<N>))
        .route(
            "/v2/participation",
            get(handlers::get_participation_keys::<N>).post(handlers::add_participation_key::<N>),
        )
        .route(
            "/v2/participation/generate/:address",
            post(handlers::generate_participation_keys::<N>),
        )
        .route(
            "/v2/participation/:participation-id",
            get(handlers::get_participation_key_by_id::<N>)
                .delete(handlers::delete_participation_key_by_id::<N>)
                .post(handlers::append_keys::<N>),
        )
        .layer(middleware::from_fn_with_state(
            tokens.admin_token.clone(),
            auth::require_token,
        ));

    // Merge all route groups
    let mut router = public.merge(authenticated).merge(admin);

    // Data API routes (follower mode only), guarded by the public API token —
    // matches go-algorand, where `data.RegisterHandlers` is wired with the
    // public middleware and only when `EnableFollowMode` is set (router.go).
    if follower_mode {
        let data = Router::new()
            .route(
                "/v2/ledger/sync",
                get(handlers::get_sync_round::<N>).delete(handlers::unset_sync_round::<N>),
            )
            .route(
                "/v2/ledger/sync/:round",
                post(handlers::set_sync_round::<N>),
            )
            .layer(middleware::from_fn_with_state(
                tokens.api_token.clone(),
                auth::require_token,
            ));
        router = router.merge(data);
    }

    // Conditionally register experimental API routes (router-level gating).
    // Handlers also check enable_experimental_api() as a belt-and-suspenders safety net.
    if tokens.enable_experimental_api {
        let experimental = Router::new()
            .route("/v2/experimental", get(handlers::experimental_check::<N>))
            .route(
                "/v2/accounts/:address/assets",
                get(handlers::account_assets_information::<N>),
            )
            .route(
                "/v2/transactions/async",
                post(handlers::raw_transaction_async::<N>),
            )
            .layer(middleware::from_fn_with_state(
                tokens.api_token.clone(),
                auth::require_token,
            ));
        router = router.merge(experimental);
    }

    router.with_state(node)
}
