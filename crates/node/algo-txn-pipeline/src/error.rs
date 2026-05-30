//! Error type for the transaction pipeline.

use algo_kmd_client::KmdError;

/// Errors produced while building, signing, submitting, or confirming a
/// transaction through the [`TxnPipeline`](crate::TxnPipeline).
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// A keyreg builder input was malformed (e.g. a participation key field of
    /// the wrong size, or a missing state-proof key). Mirrors the validation in
    /// go-algorand's `libgoal.generateRegistrationTransaction`.
    #[error("invalid key registration input: {0}")]
    InvalidKeyreg(String),

    /// The requested validity window is invalid (e.g. `last_valid < first_valid`).
    #[error("invalid transaction validity window: {0}")]
    InvalidValidity(String),

    /// kmd signing requires a kmd client, but the pipeline was built without one.
    #[error("no kmd client configured; cannot sign transactions")]
    NoKmdClient,

    /// The transaction pool rejected the submitted transaction.
    #[error("transaction {txid} rejected by the pool: {pool_error}")]
    PoolRejected {
        /// The transaction id reported by the node.
        txid: String,
        /// The pool's rejection reason.
        pool_error: String,
    },

    /// The transaction did not confirm within the allotted rounds.
    #[error("transaction {txid} not confirmed within {rounds} rounds")]
    NotConfirmed {
        /// The transaction id being awaited.
        txid: String,
        /// The number of rounds waited.
        rounds: u64,
    },

    /// An error talking to algod.
    #[error("algod request failed: {0}")]
    Algod(#[from] algo_error::AlgoError),

    /// An error talking to kmd.
    #[error("kmd request failed: {0}")]
    Kmd(#[from] KmdError),
}

/// Convenience result alias for pipeline operations.
pub type Result<T> = std::result::Result<T, PipelineError>;
