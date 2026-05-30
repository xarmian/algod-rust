//! `algo-txn-pipeline` — the shared build → sign → submit → confirm path for
//! the Rust operator toolchain (`goal-rust`, and Phase C `clerk`).
//!
//! This crate composes the algod REST client (`algo-rest-client`) and the kmd
//! wallet client (`algo-kmd-client`) into a single [`TxnPipeline`], plus pure,
//! unit-testable transaction builders. It lives in the node/client layer rather
//! than `core/` because it depends on async networking — `core/*` crates must
//! not (see `docs/CRATE_ARCHITECTURE.md`).
//!
//! Today it ships the [`KeyregBuilder`] (key registration); Phase C extends the
//! pipeline with payment / asset-transfer / asset-config / asset-freeze /
//! application builders, each a small follow-on against this same surface.

mod error;
mod keyreg;
mod pipeline;

pub use error::{PipelineError, Result};
pub use keyreg::KeyregBuilder;
pub use pipeline::TxnPipeline;

// Re-export the client-layer types a consumer needs so they don't have to
// depend on `algo-rest-client` directly just to name a pipeline input/output.
pub use algo_rest_client::{AccountParticipation, PendingTxnInfo, SuggestedParams, TxId};
